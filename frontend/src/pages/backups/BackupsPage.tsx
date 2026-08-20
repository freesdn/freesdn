/* eslint-disable @typescript-eslint/no-explicit-any */
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useState, useMemo, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';
import { useSiteStore } from '@/stores/siteStore';
import {
  Archive,
  Plus,
  Search,
  Filter,
  MoreVertical,
  Download,
  Upload,
  Trash2,
  RefreshCw,
  Calendar,
  Clock,
  HardDrive,
  Cloud,
  Server,
  CheckCircle,
  XCircle,
  Loader2,
  RotateCcw,
  Play,
  Pause,
  Settings2,
  Shield,
  AlertTriangle,
  Eye,
  Timer,
  Database,
  FileJson,
  Info,
  History,
  FolderSync,
} from 'lucide-react';
import { PageHeader, PageTabs, type PageTab } from '@/components/layout';
import { StatusBadge, type StatusVariant } from '@/components/ui/status-indicator';
import { EmptyState } from '@/components/ui/empty-state';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Alert, AlertTitle, AlertDescription } from '@/components/ui/alert';
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
import { FormDialog } from '@/components/ui/form-dialog';
import { FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Card, CardContent } from '@/components/ui/card';
import { StatsGrid } from '@/components/ui/stats-grid';
import { api, getApiErrorMessage, backupApi } from '@/lib/api';
import type { BackupManifestPreview } from '@/lib/api';
import { Checkbox } from '@/components/ui/checkbox';
import { cn } from '@/lib/utils';
import { useNotificationsStore } from '@/stores';

interface Backup {
  id: string;
  name: string;
  description: string | null;
  backup_type: string;
  status: string;
  progress: number;
  started_at: string | null;
  completed_at: string | null;
  storage_type: string;
  storage_path: string | null;
  storage_location_id: string | null;
  file_size: number | null;
  site_id: string | null;
  device_ids: string[];
  include_devices: boolean;
  include_vlans: boolean;
  include_ssids: boolean;
  include_users: boolean;
  include_automation: boolean;
  is_encrypted: boolean;
  include_secrets: boolean;
  retention_days: number;
  expires_at: string | null;
  error_message: string | null;
  created_at: string;
  created_by_id: string | null;
  schedule_id: string | null;
}

interface BackupSchedule {
  id: string;
  name: string;
  description: string | null;
  cron_expression: string | null;
  timezone: string;
  backup_type: string;
  site_id: string | null;
  device_ids: string[];
  include_devices: boolean;
  include_vlans: boolean;
  include_ssids: boolean;
  include_users: boolean;
  include_automation: boolean;
  storage_type: string;
  storage_location_id: string | null;
  is_encrypted: boolean;
  retention_days: number;
  max_backups: number;
  is_enabled: boolean;
  last_run_at: string | null;
  next_run_at: string | null;
  created_at: string;
}

interface BackupFormData {
  name: string;
  description: string;
  backup_type: string;
  site_id: string;
  device_ids: string[];
  include_devices: boolean;
  include_vlans: boolean;
  include_ssids: boolean;
  include_users: boolean;
  include_automation: boolean;
  storage_type: string;
  storage_location_id: string;
  is_encrypted: boolean;
  // Full ("vault") backup: include ALL secrets (credentials + logins), sealed under
  // the operator passphrase. include_secrets=false → the secret-free config snapshot.
  include_secrets: boolean;
  passphrase: string;
  retention_days: number;
}

interface ScheduleFormData {
  name: string;
  description: string;
  cron_expression: string;
  timezone: string;
  backup_type: string;
  site_id: string;
  device_ids: string[];
  include_devices: boolean;
  include_vlans: boolean;
  include_ssids: boolean;
  include_users: boolean;
  include_automation: boolean;
  storage_type: string;
  storage_location_id: string;
  is_encrypted: boolean;
  retention_days: number;
  max_backups: number;
  retention_type: 'days' | 'count' | 'size';
  max_size_mb: number;
}

interface RestoreOptions {
  restore_devices: boolean;
  restore_vlans: boolean;
  restore_ssids: boolean;
  restore_users: boolean;
  restore_automation: boolean;
  overwrite_existing: boolean;
  dry_run: boolean;
  // Required to restore a Full (.fsdnvault) backup — the operator passphrase.
  passphrase: string;
}

// Shape of RestoreJobResponse.dry_run_report, the per-contributor
// preview the backend computes for a dry run. Surfaced inline in the
// restore dialog so "Preview Changes" actually shows what would change.
interface DryRunContributor {
  contributor_id: string;
  status: string;
  created: Record<string, number>;
  updated: Record<string, number>;
  skipped: Record<string, number>;
  errors: string[];
  warnings: string[];
  duration_sec?: number;
}
interface DryRunReport {
  contributors: DryRunContributor[];
  summary: {
    total_created: number;
    total_updated: number;
    total_skipped: number;
    total_errors: number;
    contributors_ok: number;
    contributors_failed: number;
  };
}

const BACKUP_STATUS_VARIANT: Record<string, StatusVariant> = {
  pending: 'pending',
  in_progress: 'syncing',
  completed: 'success',
  failed: 'error',
  cancelled: 'neutral',
};

const storageIcons: Record<string, React.ReactNode> = {
  local: <HardDrive className="h-4 w-4" />,
  s3: <Cloud className="h-4 w-4" />,
  sftp: <Server className="h-4 w-4" />,
  ftp: <FolderSync className="h-4 w-4" />,
  nfs: <Server className="h-4 w-4" />,
  google_drive: <Cloud className="h-4 w-4" />,
  dropbox: <Cloud className="h-4 w-4" />,
  webdav: <Cloud className="h-4 w-4" />,
};

// Common cron presets for easy selection. Labels/descriptions are stored as
// translation key suffixes and resolved at the render site via t().
const cronPresets = [
  { labelKey: 'everyHour', value: '0 * * * *', descKey: 'everyHour' },
  { labelKey: 'daily2am', value: '0 2 * * *', descKey: 'daily2am' },
  { labelKey: 'dailyMidnight', value: '0 0 * * *', descKey: 'dailyMidnight' },
  { labelKey: 'weeklySunday', value: '0 2 * * 0', descKey: 'weeklySunday' },
  { labelKey: 'weeklyMonday', value: '0 2 * * 1', descKey: 'weeklyMonday' },
  { labelKey: 'monthly1st', value: '0 2 1 * *', descKey: 'monthly1st' },
  { labelKey: 'every6h', value: '0 */6 * * *', descKey: 'every6h' },
  { labelKey: 'every12h', value: '0 */12 * * *', descKey: 'every12h' },
];

const defaultFormData: BackupFormData = {
  name: '',
  description: '',
  backup_type: 'full',
  site_id: 'all',
  device_ids: [],
  include_devices: true,
  include_vlans: true,
  include_ssids: true,
  include_users: true,
  include_automation: true,
  storage_type: 'local',
  storage_location_id: '',
  is_encrypted: true,
  include_secrets: false,
  passphrase: '',
  retention_days: 30,
};

// zod schema backing the Create Backup FormDialog. Matches BackupFormData
// shape one-to-one. `device_ids` and `storage_location_id` are managed
// outside the form (the inline UI only sets storage_type, which may carry a
// "location:<uuid>" prefix that's parsed at submit time).
const buildBackupFormSchema = (t: (key: string) => string) =>
  z.object({
    name: z.string().min(1, t('BackupsPage.validation.nameRequired')),
    description: z.string(),
    backup_type: z.string().min(1),
    site_id: z.string(),
    device_ids: z.array(z.string()),
    include_devices: z.boolean(),
    include_vlans: z.boolean(),
    include_ssids: z.boolean(),
    include_users: z.boolean(),
    include_automation: z.boolean(),
    storage_type: z.string().min(1),
    storage_location_id: z.string(),
    is_encrypted: z.boolean(),
    include_secrets: z.boolean(),
    passphrase: z.string(),
    retention_days: z.coerce.number().int().min(1).max(365),
  });
type BackupFormSchemaValues = z.infer<ReturnType<typeof buildBackupFormSchema>>;

const defaultScheduleFormData: ScheduleFormData = {
  name: '',
  description: '',
  cron_expression: '0 2 * * *',
  timezone: 'UTC',
  backup_type: 'full',
  site_id: '',
  device_ids: [],
  include_devices: true,
  include_vlans: true,
  include_ssids: true,
  include_users: true,
  include_automation: true,
  storage_type: 'local',
  storage_location_id: '',
  is_encrypted: true,
  retention_days: 30,
  max_backups: 7,
  retention_type: 'count',
  max_size_mb: 1024,
};

const defaultRestoreOptions: RestoreOptions = {
  restore_devices: true,
  restore_vlans: true,
  restore_ssids: true,
  restore_users: false,
  restore_automation: true,
  overwrite_existing: false,
  dry_run: false,
  passphrase: '',
};

function formatBytes(bytes: number | null): string {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDate(date: string | null): string {
  if (!date) return '-';
  return new Date(date).toLocaleString();
}

// Human labels for the DB enum strings we'd otherwise render raw
// (``rollback_slot``, ``device_config``, ``google_drive`` …). Operators
// should never see snake_case identifiers in the UI. The translatable
// labels live under BackupsPage.backupTypeLabels.* / storageTypeLabels.*;
// these maps hold the key suffix per enum value.
const BACKUP_TYPE_LABEL_KEYS: Record<string, string> = {
  full: 'full',
  device_config: 'deviceConfig',
  site_config: 'siteConfig',
  rollback_slot: 'rollbackSlot',
};
type TFn = (key: string, options?: Record<string, unknown>) => string;
function humanizeBackupType(t: TFn, type: string | null | undefined): string {
  if (!type) return '-';
  const keySuffix = BACKUP_TYPE_LABEL_KEYS[type];
  if (keySuffix) return t(`BackupsPage.backupTypeLabels.${keySuffix}`);
  return type.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

const STORAGE_TYPE_LABEL_KEYS: Record<string, string> = {
  local: 'local',
  s3: 's3',
  sftp: 'sftp',
  ftp: 'ftp',
  nfs: 'nfs',
  google_drive: 'googleDrive',
  dropbox: 'dropbox',
  webdav: 'webdav',
};
function humanizeStorageType(t: TFn, type: string | null | undefined): string {
  if (!type) return '-';
  const keySuffix = STORAGE_TYPE_LABEL_KEYS[type];
  if (keySuffix) return t(`BackupsPage.storageTypeLabels.${keySuffix}`);
  return type.replace(/_/g, ' ');
}

function formatRelativeTime(t: TFn, date: string | null): string {
  if (!date) return t('BackupsPage.time.never');
  const now = new Date();
  const then = new Date(date);
  const diff = now.getTime() - then.getTime();

  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);

  if (minutes < 1) return t('BackupsPage.time.justNow');
  if (minutes < 60) return t('BackupsPage.time.minutesAgo', { n: minutes });
  if (hours < 24) return t('BackupsPage.time.hoursAgo', { n: hours });
  if (days < 7) return t('BackupsPage.time.daysAgo', { n: days });
  return formatDate(date);
}

function getNextCronRun(t: TFn, cronExpression: string | null | undefined): string {
  // Simple approximation for display
  if (!cronExpression) return t('BackupsPage.cron.invalid');
  const parts = cronExpression.split(' ');
  if (parts.length !== 5) return t('BackupsPage.cron.invalid');

  const [minute, hour, dayOfMonth, _month, dayOfWeek] = parts;

  if (dayOfWeek !== '*' && dayOfMonth === '*') {
    const dayKeys = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
    const dayKey = dayKeys[parseInt(dayOfWeek)];
    const day = dayKey ? t(`BackupsPage.cron.days.${dayKey}`) : t('BackupsPage.cron.runWord');
    return t('BackupsPage.cron.nextDayAt', { day, time: `${hour}:${minute.padStart(2, '0')}` });
  }
  if (dayOfMonth !== '*') {
    const ordinal = `${dayOfMonth}${['st', 'nd', 'rd'][parseInt(dayOfMonth) - 1] || 'th'}`;
    return t('BackupsPage.cron.dayOfMonthAt', { ordinal, time: `${hour}:${minute.padStart(2, '0')}` });
  }
  if (hour.includes('/')) {
    return t('BackupsPage.cron.everyNHours', { n: hour.split('/')[1] });
  }
  return t('BackupsPage.cron.dailyAt', { time: `${hour}:${minute.padStart(2, '0')}` });
}

export default function BackupsPage() {
  const { t } = useTranslation('backup');
  const queryClient = useQueryClient();
  const { addNotification } = useNotificationsStore();
  // Build the zod schema with localized validation messages. Memoized on t
  // so it only rebuilds when the active language changes.
  const backupFormSchema = useMemo(() => buildBackupFormSchema(t), [t]);
  // Localized label for a backup status enum value. Falls back to the
  // humanized raw value for any status we don't have a translation for.
  const statusLabel = (status: string): string => {
    const map: Record<string, string> = {
      pending: 'BackupsPage.status.pending',
      in_progress: 'BackupsPage.status.inProgress',
      completed: 'BackupsPage.status.completed',
      failed: 'BackupsPage.status.failed',
      cancelled: 'BackupsPage.status.cancelled',
    };
    const key = map[status];
    return key ? t(key) : status.replace('_', ' ');
  };
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selectedBackupIds, setSelectedBackupIds] = useState<Set<string>>(new Set());
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [restoreDialogBackup, setRestoreDialogBackup] = useState<Backup | null>(null);
  
  // New state for enhanced features
  const [isScheduleDialogOpen, setIsScheduleDialogOpen] = useState(false);
  const [scheduleFormData, setScheduleFormData] = useState<ScheduleFormData>(defaultScheduleFormData);
  const [editingSchedule, setEditingSchedule] = useState<BackupSchedule | null>(null);
  const [restoreOptions, setRestoreOptions] = useState<RestoreOptions>(defaultRestoreOptions);
  // typed-confirmation required before destructive (non-dry-run)
  // restore can be triggered. User must type the backup name OR "RESTORE".
  const [restoreConfirmText, setRestoreConfirmText] = useState('');
  // Result of the most recent "Preview Changes" (dry run) for the open
  // restore dialog. Rendered inline so the operator can actually review
  // the previewed changes before committing. Cleared whenever the
  // selection changes (the preview would be stale) or the dialog closes.
  const [dryRunResult, setDryRunResult] = useState<DryRunReport | null>(null);
  // Enterprise backup v2: which manifest contributors the operator has
  // selected to restore. null = "all" (the default before the manifest
  // loads, and the value sent when every restorable contributor is
  // checked). A Set of ids = restore only those.
  const [selectedContributors, setSelectedContributors] = useState<Set<string> | null>(null);
  const [deleteScheduleId, setDeleteScheduleId] = useState<string | null>(null);
  const [viewHistoryBackup, setViewHistoryBackup] = useState<Backup | null>(null);
  const [showCronHelp, setShowCronHelp] = useState(false);
  
  // Instant export/import state
  const [isExporting, setIsExporting] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importPreview, setImportPreview] = useState<any>(null);
  const [showImportDialog, setShowImportDialog] = useState(false);
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // Fetch backups
  const { data: backupsData, isLoading: backupsLoading, isError: backupsError, refetch: refetchBackups } = useQuery({
    queryKey: ['backups', searchQuery, statusFilter, { siteId: selectedSiteId }],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (searchQuery) params.append('search', searchQuery);
      if (statusFilter !== 'all') params.append('status', statusFilter);
      if (selectedSiteId) params.append('site_id', selectedSiteId);
      const response = await api.get(`/backups?${params.toString()}`);
      return response.data;
    },
  });

  // Fetch schedules
  const { data: schedulesData, isLoading: schedulesLoading, isError: schedulesError, refetch: refetchSchedules } = useQuery({
    queryKey: ['backup-schedules', { siteId: selectedSiteId }],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (selectedSiteId) params.append('site_id', selectedSiteId);
      const response = await api.get(`/backups/schedules?${params.toString()}`);
      return response.data;
    },
  });

  // Fetch backup stats
  const { data: statsData, isError: statsError } = useQuery({
    queryKey: ['backup-stats', { siteId: selectedSiteId }],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (selectedSiteId) params.append('site_id', selectedSiteId);
      const response = await api.get(`/backups/stats?${params.toString()}`);
      return response.data;
    },
  });

  // Fetch sites for dropdown
  const { data: sitesData, isError: sitesError } = useQuery({
    queryKey: ['sites', { siteId: selectedSiteId }],
    queryFn: async () => {
      const response = await api.get('/sites');
      return response.data;
    },
  });

  // Fetch storage locations
  const { data: storageLocations, isError: storageError, refetch: _refetchStorageLocations } = useQuery({
    queryKey: ['storage-locations', { siteId: selectedSiteId }],
    queryFn: async () => {
      const response = await api.get('/backups/storage-locations');
      return response.data;
    },
  });

  // Fetch supported storage types
  const { data: _supportedStorageTypes, isError: storageTypesError } = useQuery({
    queryKey: ['storage-types', { siteId: selectedSiteId }],
    queryFn: async () => {
      const response = await api.get('/backups/storage-locations/types/supported');
      return response.data;
    },
  });

  // Create backup mutation
  const createMutation = useMutation({
    mutationFn: async (data: BackupFormData) => {
      const response = await api.post('/backups', data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['backups'] });
      queryClient.invalidateQueries({ queryKey: ['backup-stats'] });
      setIsDialogOpen(false);
      addNotification({
        type: 'success',
        title: t('BackupsPage.toasts.backupStarted.title'),
        message: t('BackupsPage.toasts.backupStarted.message'),
      });
    },
    onError: (error: any) => {
      addNotification({
        type: 'error',
        title: t('BackupsPage.toasts.error'),
        message: getApiErrorMessage(error, t('BackupsPage.toasts.createBackupFailed')),
      });
    },
  });

  // Delete backup mutation
  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/backups/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['backups'] });
      queryClient.invalidateQueries({ queryKey: ['backup-stats'] });
      setDeleteConfirmId(null);
      addNotification({
        type: 'success',
        title: t('BackupsPage.toasts.backupDeleted.title'),
        message: t('BackupsPage.toasts.backupDeleted.message'),
      });
    },
    onError: (error: any) => {
      addNotification({
        type: 'error',
        title: t('BackupsPage.toasts.error'),
        message: getApiErrorMessage(error, t('BackupsPage.toasts.deleteBackupFailed')),
      });
    },
  });

  // Toggle schedule mutation
  const toggleScheduleMutation = useMutation({
    mutationFn: async ({ id, is_enabled }: { id: string; is_enabled: boolean }) => {
      const response = await api.post(`/backups/schedules/${id}/toggle`, { is_enabled });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['backup-schedules'] });
      addNotification({
        type: 'success',
        title: t('BackupsPage.toasts.scheduleUpdated.title'),
        message: t('BackupsPage.toasts.scheduleToggled.message'),
      });
    },
    onError: (error: any) => {
      addNotification({
        type: 'error',
        title: t('BackupsPage.toasts.error'),
        message: getApiErrorMessage(error, t('BackupsPage.toasts.toggleScheduleFailed')),
      });
    },
  });

  // Restore mutation
  const restoreMutation = useMutation({
    mutationFn: async (
      data: { backup_id: string; contributors?: string[] } & RestoreOptions,
    ) => {
      const response = await api.post('/backups/restore', data);
      return response.data;
    },
    onSuccess: (data) => {
      if (data?.dry_run) {
        // Keep the dialog OPEN and surface what the dry run found, so
        // "Preview Changes" is actually reviewable (it previously just
        // closed the dialog with a toast and discarded the report).
        setDryRunResult((data.dry_run_report as DryRunReport) ?? null);
        queryClient.invalidateQueries({ queryKey: ['backups'] });
        addNotification({
          type: 'success',
          title: t('BackupsPage.toasts.dryRunComplete.title'),
          message: t('BackupsPage.toasts.dryRunComplete.message'),
        });
        return;
      }
      setRestoreDialogBackup(null);
      setRestoreConfirmText('');
      setDryRunResult(null);
      queryClient.invalidateQueries({ queryKey: ['backups'] });
      addNotification({
        type: 'success',
        title: t('BackupsPage.toasts.restoreStarted.title'),
        message: t('BackupsPage.toasts.restoreStarted.message'),
      });
    },
    onError: (error: any) => {
      addNotification({
        type: 'error',
        title: t('BackupsPage.toasts.error'),
        message: getApiErrorMessage(error, t('BackupsPage.toasts.restoreFailed')),
      });
    },
  });

  // Manifest preview for the selective-restore dialog. Fetched when the
  // restore dialog opens; lets the operator pick which modules
  // (contributors) to restore + greys out incompatible ones.
  const {
    data: restoreManifest,
    isLoading: manifestLoading,
    isError: manifestError,
  } = useQuery<BackupManifestPreview>({
    queryKey: ['backup-manifest', restoreDialogBackup?.id],
    queryFn: async () => {
      const res = await backupApi.previewManifest(restoreDialogBackup!.id);
      return res.data;
    },
    enabled: !!restoreDialogBackup,
    staleTime: 60_000,
  });

  // Build the contributor list the dialog drives off, only restorable
  // ones can be toggled. ``selectedContributors === null`` means "all
  // restorable" (the default). Helper to decide if a given id is checked.
  const isContributorChecked = (id: string): boolean =>
    selectedContributors === null || selectedContributors.has(id);

  const toggleContributor = (id: string, restorableIds: string[]): void => {
    // Any selection change invalidates a previously-run preview.
    setDryRunResult(null);
    setSelectedContributors((prev) => {
      // Start from the explicit set, or the full restorable set if we
      // were in "all" mode.
      const next = new Set(prev ?? restorableIds);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      // If the operator re-checked everything, collapse back to null
      // ("all") so the restore request omits the contributors filter.
      if (restorableIds.every((r) => next.has(r)) && next.size === restorableIds.length) {
        return null;
      }
      return next;
    });
  };

  // The contributor ids to send with the restore request: undefined when
  // "all" is selected (omit the filter), else the explicit array.
  const restoreContributorSelection = (): string[] | undefined => {
    if (selectedContributors === null) return undefined;
    return Array.from(selectedContributors);
  };

  // Patch a restore option and drop any previewed dry-run result, which
  // would no longer reflect the new options.
  const updateRestoreOption = (patch: Partial<RestoreOptions>): void => {
    setRestoreOptions((prev) => ({ ...prev, ...patch }));
    setDryRunResult(null);
  };

  // Reset the contributor selection to "all" whenever the restore dialog
  // opens for a different backup (or closes). Keying on the backup id
  // avoids carrying a stale selection across restores without touching
  // every open/close call site.
  useEffect(() => {
    setSelectedContributors(null);
    setDryRunResult(null);
  }, [restoreDialogBackup?.id]);

  // Create schedule mutation
  const createScheduleMutation = useMutation({
    mutationFn: async (data: Partial<ScheduleFormData>) => {
      const response = await api.post('/backups/schedules', data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['backup-schedules'] });
      setIsScheduleDialogOpen(false);
      setScheduleFormData(defaultScheduleFormData);
      addNotification({
        type: 'success',
        title: t('BackupsPage.toasts.scheduleCreated.title'),
        message: t('BackupsPage.toasts.scheduleCreated.message'),
      });
    },
    onError: (error: any) => {
      addNotification({
        type: 'error',
        title: t('BackupsPage.toasts.error'),
        message: getApiErrorMessage(error, t('BackupsPage.toasts.createScheduleFailed')),
      });
    },
  });

  // Update schedule mutation
  const updateScheduleMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: Partial<ScheduleFormData> }) => {
      const response = await api.put(`/backups/schedules/${id}`, data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['backup-schedules'] });
      setIsScheduleDialogOpen(false);
      setEditingSchedule(null);
      setScheduleFormData(defaultScheduleFormData);
      addNotification({
        type: 'success',
        title: t('BackupsPage.toasts.scheduleUpdated.title'),
        message: t('BackupsPage.toasts.scheduleUpdated.message'),
      });
    },
    onError: (error: any) => {
      addNotification({
        type: 'error',
        title: t('BackupsPage.toasts.error'),
        message: getApiErrorMessage(error, t('BackupsPage.toasts.updateScheduleFailed')),
      });
    },
  });

  // Delete schedule mutation
  const deleteScheduleMutation = useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/backups/schedules/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['backup-schedules'] });
      setDeleteScheduleId(null);
      addNotification({
        type: 'success',
        title: t('BackupsPage.toasts.scheduleDeleted.title'),
        message: t('BackupsPage.toasts.scheduleDeleted.message'),
      });
    },
    onError: (error: any) => {
      addNotification({
        type: 'error',
        title: t('BackupsPage.toasts.error'),
        message: getApiErrorMessage(error, t('BackupsPage.toasts.deleteScheduleFailed')),
      });
    },
  });

  // Download backup mutation
  const downloadBackupMutation = useMutation({
    mutationFn: async (backup: Backup) => {
      const response = await api.get(`/backups/${backup.id}/download`, {
        responseType: 'blob',
      });
      // Get filename from Content-Disposition header or use .fsdn extension
      const contentDisposition = response.headers?.['content-disposition'];
      let filename = `${backup.name}.fsdn`;
      if (contentDisposition) {
        const match = contentDisposition.match(/filename="?(.+?)"?$/);
        if (match) filename = match[1];
      }
      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    },
    onError: (error: any) => {
      addNotification({
        type: 'error',
        title: t('BackupsPage.toasts.downloadFailed.title'),
        message: getApiErrorMessage(error, t('BackupsPage.toasts.downloadBackupFailed')),
      });
    },
  });

  const resetScheduleForm = () => {
    setScheduleFormData(defaultScheduleFormData);
    setEditingSchedule(null);
  };

  const handleScheduleSubmit = () => {
    // Parse storage type - might be a location reference like "location:uuid"
    let storageType = scheduleFormData.storage_type;
    let storageLocationId: string | null = null;
    
    if (scheduleFormData.storage_type.startsWith('location:')) {
      storageLocationId = scheduleFormData.storage_type.replace('location:', '');
      // Get the storage type from the location
      const location = storageLocations?.find((loc: any) => loc.id === storageLocationId);
      storageType = location?.storage_type || 'local';
    }
    
    const submitData = {
      name: scheduleFormData.name,
      description: scheduleFormData.description || null,
      cron_expression: scheduleFormData.cron_expression,
      timezone: scheduleFormData.timezone,
      backup_type: scheduleFormData.backup_type,
      site_id: scheduleFormData.site_id || null,
      device_ids: scheduleFormData.device_ids,
      include_devices: scheduleFormData.include_devices,
      include_vlans: scheduleFormData.include_vlans,
      include_ssids: scheduleFormData.include_ssids,
      include_users: scheduleFormData.include_users,
      include_automation: scheduleFormData.include_automation,
      storage_type: storageType,
      storage_location_id: storageLocationId,
      is_encrypted: scheduleFormData.is_encrypted,
      retention_days: scheduleFormData.retention_days,
      max_backups: scheduleFormData.max_backups,
    };

    if (editingSchedule) {
      updateScheduleMutation.mutate({ id: editingSchedule.id, data: submitData as any });
    } else {
      createScheduleMutation.mutate(submitData as any);
    }
  };

  const handleEditSchedule = (schedule: BackupSchedule) => {
    setEditingSchedule(schedule);
    // If schedule has a storage_location_id, use it; otherwise use the storage_type
    const storageValue = schedule.storage_location_id 
      ? `location:${schedule.storage_location_id}` 
      : schedule.storage_type;
    setScheduleFormData({
      name: schedule.name,
      description: schedule.description || '',
      cron_expression: schedule.cron_expression ?? '',
      timezone: schedule.timezone,
      backup_type: schedule.backup_type,
      site_id: schedule.site_id || '',
      device_ids: schedule.device_ids || [],
      include_devices: schedule.include_devices,
      include_vlans: schedule.include_vlans,
      include_ssids: schedule.include_ssids,
      include_users: schedule.include_users,
      include_automation: schedule.include_automation,
      storage_type: storageValue,
      storage_location_id: schedule.storage_location_id || '',
      is_encrypted: schedule.is_encrypted,
      retention_days: schedule.retention_days,
      max_backups: schedule.max_backups,
      retention_type: 'count',
      max_size_mb: 1024,
    });
    setIsScheduleDialogOpen(true);
  };

  // Handle instant export (pfSense/OPNsense style)
  const handleInstantExport = async () => {
    setIsExporting(true);
    try {
      const response = await api.get('/backups/export', {
        params: {
          include_devices: true,
          include_vlans: true,
          include_ssids: true,
          include_users: false,
          include_automation: true,
          include_settings: true,
          compress: false,
        },
        responseType: 'blob',
      });
      
      // Get filename from response headers or generate one
      const contentDisposition = response.headers['content-disposition'];
      let filename = 'freesdn_config.json';
      if (contentDisposition) {
        const matches = /filename="?([^"]+)"?/.exec(contentDisposition);
        if (matches && matches[1]) {
          filename = matches[1];
        }
      }
      
      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
      addNotification({
        type: 'success',
        title: t('BackupsPage.toasts.exportComplete.title'),
        message: t('BackupsPage.toasts.exportComplete.message'),
      });
    } catch (error: unknown) {
      console.error('Export failed:', error);
      addNotification({
        type: 'error',
        title: t('BackupsPage.toasts.exportFailed.title'),
        message: getApiErrorMessage(error, t('BackupsPage.toasts.exportConfigFailed')),
      });
    } finally {
      setIsExporting(false);
    }
  };

  // Handle import file selection
  const handleImportClick = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json,.gz,.fsdn';
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (file) {
        setImportFile(file);
        setIsImporting(true);
        try {
          // Do a dry run first to preview
          const formData = new FormData();
          formData.append('file', file);
          const response = await api.post('/backups/import', formData, {
            params: { dry_run: true },
            headers: { 'Content-Type': 'multipart/form-data' },
          });
          setImportPreview(response.data);
          setShowImportDialog(true);
        } catch (error: unknown) {
          console.error('Import preview failed:', error);
          addNotification({
            type: 'error',
            title: t('BackupsPage.toasts.importFailed.title'),
            message: getApiErrorMessage(error, t('BackupsPage.toasts.readImportFailed')),
          });
          setImportFile(null);
        } finally {
          setIsImporting(false);
        }
      }
    };
    input.click();
  };

  // Execute actual import
  const handleConfirmImport = async () => {
    if (!importFile) return;
    
    setIsImporting(true);
    try {
      const formData = new FormData();
      formData.append('file', importFile);
      await api.post('/backups/import', formData, {
        params: { dry_run: false },
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      
      addNotification({
        type: 'success',
        title: t('BackupsPage.toasts.importComplete.title'),
        message: t('BackupsPage.toasts.importComplete.message'),
      });

      setShowImportDialog(false);
      setImportFile(null);
      setImportPreview(null);
      
      // Refresh all data
      queryClient.invalidateQueries();
    } catch (error: unknown) {
      console.error('Import failed:', error);
      addNotification({
        type: 'error',
        title: t('BackupsPage.toasts.importFailed.title'),
        message: getApiErrorMessage(error, t('BackupsPage.toasts.importConfigFailed')),
      });
    } finally {
      setIsImporting(false);
    }
  };

  // would_import[key] is a per-entity summary object { created, updated, skipped, ... }.
  // Render the numeric "will be affected" count (created + updated) so we never
  // render the raw object as a React child.
  const importPreviewCount = (key: string): number => {
    const entry = importPreview?.would_import?.[key];
    if (!entry || typeof entry !== 'object') return 0;
    return (entry.created || 0) + (entry.updated || 0);
  };

  const backups = useMemo(() => backupsData?.items ?? [], [backupsData?.items]);
  const schedules = schedulesData || [];
  const sites = sitesData?.items || [];
  const stats = statsData || {};

  // Computed values for UI
  const completedBackups = useMemo(() => 
    backups.filter((b: Backup) => b.status === 'completed'),
    [backups]
  );
  
  // Storage Used reflects the backend aggregate across ALL backups, not just
  // the current page. Fall back to the page sum if the aggregate is absent.
  const totalStorageUsed = useMemo(() =>
    stats.total_size_bytes ??
      backups.reduce((sum: number, b: Backup) => sum + (b.file_size || 0), 0),
    [stats.total_size_bytes, backups]
  );

  const hasQueryError = backupsError || schedulesError || statsError || sitesError || storageError || storageTypesError;

  return (
    <div className="space-y-6">
        {/* Header */}
        <PageHeader
          title={t('BackupsPage.header.title')}
          description={t('BackupsPage.header.description')}
          icon={Archive}
          onRefresh={() => {
            refetchBackups();
            refetchSchedules();
          }}
          refreshing={backupsLoading}
          primaryAction={{
            label: t('BackupsPage.actions.newBackup'),
            icon: Plus,
            onClick: () => {
              setIsDialogOpen(true);
            }
          }}
        />

        {/* Scope banner, readiness distinguish this
            portable-config feature from full-system disaster recovery. */}
        <Alert>
          <Info className="h-4 w-4" />
          <AlertTitle>{t('BackupsPage.scopeBanner.title')}</AlertTitle>
          <AlertDescription>
            {t('BackupsPage.scopeBanner.part1Before')} <code>.fsdn</code>{' '}
            {t('BackupsPage.scopeBanner.part1After')} <code>pg-backup</code>{' '}
            {t('BackupsPage.scopeBanner.part2')}{' '}
            <a
              href="https://docs.freesdn.org/deploy/backups-and-restore/"
              target="_blank"
              rel="noopener noreferrer"
              className="font-medium underline underline-offset-2"
            >
              the backup &amp; restore guide
            </a>.
          </AlertDescription>
        </Alert>

        {hasQueryError && (
          <Card className="border-destructive">
            <CardContent noOffset className="p-4 flex items-center gap-3">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              <span className="text-sm">{t('BackupsPage.errors.partialLoad')}</span>
            </CardContent>
          </Card>
        )}

        {/* Quick Actions Bar */}
        <Card>
          <CardContent noOffset className="flex items-center justify-between p-4">
            <div className="flex items-center gap-2">
              <FileJson className="h-5 w-5 text-primary" />
              <div>
                <h3 className="text-sm font-medium text-foreground">{t('BackupsPage.quickActions.title')}</h3>
                <p className="text-xs text-muted-foreground">{t('BackupsPage.quickActions.subtitle')}</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={handleInstantExport}
                disabled={isExporting}
                className="gap-2"
              >
                {isExporting ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Download className="h-4 w-4" />
                )}
                {isExporting ? t('BackupsPage.quickActions.exporting') : t('BackupsPage.quickActions.exportConfig')}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={handleImportClick}
                disabled={isImporting}
                className="gap-2"
              >
                {isImporting ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Upload className="h-4 w-4" />
                )}
                {isImporting ? t('BackupsPage.quickActions.reading') : t('BackupsPage.quickActions.importConfig')}
              </Button>
              <div className="w-px h-6 bg-border" />
              <Link to="/backups/storage-locations">
                <Button variant="outline" size="sm" className="gap-2">
                  <FolderSync className="h-4 w-4" />
                  {t('BackupsPage.actions.storageLocations')}
                </Button>
              </Link>
            </div>
          </CardContent>
        </Card>

        {/* Stats Cards */}
        <StatsGrid
          columns={4}
          stats={[
            { title: t('BackupsPage.stats.totalBackups'), value: stats.total_backups || 0, icon: Archive, variant: 'primary' },
            { title: t('BackupsPage.stats.completed'), value: stats.completed_backups || 0, icon: CheckCircle, variant: 'success' },
            { title: t('BackupsPage.stats.failed'), value: stats.failed_backups || 0, icon: XCircle, variant: 'destructive' },
            {
              title: t('BackupsPage.stats.storageUsed'),
              value: formatBytes(totalStorageUsed),
              icon: HardDrive,
              variant: 'primary',
              description: t('BackupsPage.stats.activeSchedules', {
                count: schedules.filter((s: BackupSchedule) => s.is_enabled).length,
              }),
            },
          ]}
        />

        {/* Storage Locations CTA */}
        {(!storageLocations || storageLocations.length === 0) ? (
          <div className="relative overflow-hidden rounded-lg border border-dashed border-primary/40 bg-primary/5 p-6">
            <div className="flex items-center gap-4">
              <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-primary/10">
                <FolderSync className="h-6 w-6 text-primary" />
              </div>
              <div className="flex-1">
                <h3 className="text-sm font-semibold text-foreground">{t('BackupsPage.storageCta.noneTitle')}</h3>
                <p className="mt-1 text-sm text-muted-foreground">
                  {t('BackupsPage.storageCta.noneDescription')}
                </p>
              </div>
              <Link to="/backups/storage-locations">
                <Button className="gap-2 shrink-0">
                  <Settings2 className="h-4 w-4" />
                  {t('BackupsPage.storageCta.configure')}
                </Button>
              </Link>
            </div>
          </div>
        ) : (
          <Card>
            <CardContent noOffset className="flex items-center justify-between p-4">
              <div className="flex items-center gap-3">
                <FolderSync className="h-5 w-5 text-primary" />
                <div>
                  <span className="text-sm font-medium text-foreground">
                    {storageLocations.length === 1
                      ? t('BackupsPage.storageCta.countOne', { count: storageLocations.length })
                      : t('BackupsPage.storageCta.countMany', { count: storageLocations.length })}
                  </span>
                  <p className="text-xs text-muted-foreground">{t('BackupsPage.storageCta.configuredForBackups')}</p>
                </div>
              </div>
              <Link to="/backups/storage-locations">
                <Button variant="outline" size="sm" className="gap-2">
                  <Settings2 className="h-4 w-4" />
                  {t('BackupsPage.storageCta.manage')}
                </Button>
              </Link>
            </CardContent>
          </Card>
        )}

        {/* Storage Overview Panel - only show when there are backups */}
        {completedBackups.length > 0 && (
          <Card>
            <CardContent noOffset className="p-4">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Database className="h-5 w-5 text-primary" />
                  <h3 className="font-medium text-foreground">{t('BackupsPage.timeline.title')}</h3>
                </div>
                <Badge variant="outline" className="text-xs">
                  {t('BackupsPage.timeline.lastN', { count: Math.min(completedBackups.length, 10) })}
                </Badge>
              </div>
              <div className="relative">
                {/* Timeline visualization */}
                <div className="flex items-end gap-1 h-20 mb-2">
                  {completedBackups.slice(0, 10).reverse().map((backup: Backup, _idx: number) => {
                    const maxSize = Math.max(...completedBackups.slice(0, 10).map((b: Backup) => b.file_size || 1));
                    const height = Math.max(10, ((backup.file_size || 0) / maxSize) * 100);
                    return (
                      <div
                        key={backup.id}
                        // h-full + inner items-end so the percentage-height
                        // bar resolves against the 80px (h-20) container.
                        // Without h-full the wrapper is auto-height and a
                        // ``height: X%`` child collapses to 0px → invisible
                        // bars (the empty-timeline bug).
                        className="flex-1 h-full flex items-end group relative cursor-pointer"
                        onClick={() => setViewHistoryBackup(backup)}
                      >
                        <div
                          className={cn(
                            "w-full rounded-t transition-all group-hover:bg-primary",
                            backup.schedule_id ? "bg-primary/60" : "bg-primary/40"
                          )}
                          style={{ height: `${height}%` }}
                        />
                        {/* Tooltip */}
                        <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 hidden group-hover:block z-10">
                          <div className="bg-popover border border-border rounded-lg p-2 shadow-lg text-xs whitespace-nowrap">
                            <p className="font-medium">{backup.name}</p>
                            <p className="text-muted-foreground">{formatBytes(backup.file_size)}</p>
                            <p className="text-muted-foreground">{formatRelativeTime(t, backup.created_at)}</p>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>{t('BackupsPage.timeline.oldest')}</span>
                  <span>{t('BackupsPage.timeline.mostRecent')}</span>
                </div>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Tabs */}
        <PageTabs
          basePath="/backups"
          tabs={[
            {
              value: 'backups',
              label: t('BackupsPage.tabs.backups'),
              count: backups.length || undefined,
              content: (
                <div className="space-y-4">
            {/* Filters */}
            <div className="flex items-center gap-4">
              <div className="relative flex-1 max-w-md">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder={t('BackupsPage.filters.searchPlaceholder')}
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10"
                />
              </div>
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-[180px]">
                  <Filter className="h-4 w-4 mr-2" />
                  <SelectValue placeholder={t('BackupsPage.filters.statusPlaceholder')} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{t('BackupsPage.filters.allStatus')}</SelectItem>
                  <SelectItem value="pending">{t('BackupsPage.status.pending')}</SelectItem>
                  <SelectItem value="in_progress">{t('BackupsPage.status.inProgress')}</SelectItem>
                  <SelectItem value="completed">{t('BackupsPage.status.completed')}</SelectItem>
                  <SelectItem value="failed">{t('BackupsPage.status.failed')}</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Backups Table */}
            {backupsLoading ? (
              <div className="space-y-2">
                {[...Array(5)].map((_, i) => (
                  <div
                    key={i}
                    className="h-16 bg-card border border-border rounded-lg animate-pulse"
                  />
                ))}
              </div>
            ) : backups.length === 0 ? (
              <EmptyState
                icon={Archive}
                title={t('BackupsPage.empty.noBackups.title')}
                description={t('BackupsPage.empty.noBackups.description')}
                action={{ label: t('BackupsPage.actions.newBackup'), onClick: () => setIsDialogOpen(true), icon: Plus }}
                variant="card"
              />
            ) : (
              <div className="space-y-2">
                {backups.map((backup: Backup) => (
                  <div
                    key={backup.id}
                    className="bg-card border border-border rounded-lg p-4 hover:border-primary/50 transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-4">
                        <input
                          type="checkbox"
                          checked={selectedBackupIds.has(backup.id)}
                          onChange={() => {
                            setSelectedBackupIds((prev) => {
                              const next = new Set(prev);
                              if (next.has(backup.id)) next.delete(backup.id); else next.add(backup.id);
                              return next;
                            });
                          }}
                          aria-label={t('BackupsPage.actions.selectItem', { name: backup.name })}
                          className="h-4 w-4"
                        />
                        <div className="h-10 w-10 rounded-lg bg-primary/20 flex items-center justify-center">
                          {storageIcons[backup.storage_type] || <Archive className="h-5 w-5" />}
                        </div>
                        <div>
                          <h3 className="font-medium text-foreground flex items-center gap-2">
                            {backup.name}
                            {backup.backup_type === 'rollback_slot' && (
                              <Badge
                                variant="outline"
                                className="text-[10px] border-amber-500/40 text-amber-500"
                                title={t('BackupsPage.rollbackBadge.tooltip')}
                              >
                                {t('BackupsPage.rollbackBadge.label')}
                              </Badge>
                            )}
                          </h3>
                          <div className="flex items-center gap-2 text-sm text-muted-foreground">
                            <span>{formatDate(backup.created_at)}</span>
                            <span>•</span>
                            <span>{formatBytes(backup.file_size)}</span>
                            {backup.is_encrypted && (
                              <>
                                <span>•</span>
                                <Badge variant="outline" className="text-xs">{t('BackupsPage.common.encrypted')}</Badge>
                              </>
                            )}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-4">
                        {backup.status === 'in_progress' && (
                          <div className="w-32">
                            <Progress value={backup.progress} className="h-2" />
                            <span className="text-xs text-muted-foreground">
                              {backup.progress}%
                            </span>
                          </div>
                        )}
                        <StatusBadge variant={BACKUP_STATUS_VARIANT[backup.status] || 'neutral'}>
                          {statusLabel(backup.status)}
                        </StatusBadge>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon" className="h-8 w-8">
                              <MoreVertical className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            {backup.status === 'completed' && (
                              <>
                                <DropdownMenuItem
                                  onClick={() => downloadBackupMutation.mutate(backup)}
                                >
                                  <Download className="h-4 w-4 mr-2" />
                                  {t('BackupsPage.actions.download')}
                                </DropdownMenuItem>
                                <DropdownMenuItem
                                  onClick={() => {
                                    setRestoreDialogBackup(backup);
                                    setRestoreOptions(defaultRestoreOptions);
                                    setRestoreConfirmText('');
                                  }}
                                >
                                  <RotateCcw className="h-4 w-4 mr-2" />
                                  {t('BackupsPage.actions.restore')}
                                </DropdownMenuItem>
                                <DropdownMenuItem
                                  onClick={() => setViewHistoryBackup(backup)}
                                >
                                  <Eye className="h-4 w-4 mr-2" />
                                  {t('BackupsPage.actions.viewDetails')}
                                </DropdownMenuItem>
                                <DropdownMenuSeparator />
                              </>
                            )}
                            <DropdownMenuItem
                              className="text-destructive"
                              onClick={() => setDeleteConfirmId(backup.id)}
                            >
                              <Trash2 className="h-4 w-4 mr-2" />
                              {t('BackupsPage.actions.delete')}
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>
                    </div>

                    {backup.error_message && (
                      <div className="mt-2 p-2 bg-destructive/10 border border-destructive/20 rounded text-sm text-destructive">
                        {backup.error_message}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
                </div>
              ),
            },
            {
              value: 'schedules',
              label: t('BackupsPage.tabs.schedules'),
              count: schedules.length || undefined,
              content: (
                <div className="space-y-4">
            {/* Schedule Header with Create Button */}
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-medium text-foreground">{t('BackupsPage.schedules.heading')}</h3>
                <p className="text-sm text-muted-foreground">{t('BackupsPage.schedules.subheading')}</p>
              </div>
              <Button
                className="gap-2"
                onClick={() => {
                  resetScheduleForm();
                  setIsScheduleDialogOpen(true);
                }}
              >
                <Plus className="h-4 w-4" />
                {t('BackupsPage.actions.createSchedule')}
              </Button>
            </div>

            {/* Schedules List */}
            {schedulesLoading ? (
              <div className="space-y-2">
                {[...Array(3)].map((_, i) => (
                  <div
                    key={i}
                    className="h-24 bg-card border border-border rounded-lg animate-pulse"
                  />
                ))}
              </div>
            ) : schedules.length === 0 ? (
              <EmptyState
                icon={Calendar}
                title={t('BackupsPage.empty.noSchedules.title')}
                description={t('BackupsPage.empty.noSchedules.description')}
                action={{
                  label: t('BackupsPage.actions.createSchedule'),
                  onClick: () => { resetScheduleForm(); setIsScheduleDialogOpen(true); },
                  icon: Plus,
                }}
                variant="card"
              />
            ) : (
              <div className="space-y-3">
                {schedules.map((schedule: BackupSchedule) => (
                  <div
                    key={schedule.id}
                    className={cn(
                      "bg-card border rounded-lg p-4 transition-all",
                      schedule.is_enabled 
                        ? "border-primary/30 hover:border-primary/50" 
                        : "border-border hover:border-border/80 opacity-75"
                    )}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex items-start gap-4">
                        <div
                          className={cn(
                            'h-12 w-12 rounded-lg flex items-center justify-center',
                            schedule.is_enabled
                              ? 'bg-primary/20 text-primary'
                              : 'bg-muted text-muted-foreground'
                          )}
                        >
                          {schedule.is_enabled ? (
                            <Timer className="h-6 w-6" />
                          ) : (
                            <Pause className="h-6 w-6" />
                          )}
                        </div>
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <h3 className="font-medium text-foreground">{schedule.name}</h3>
                            <Badge variant={schedule.is_enabled ? 'default' : 'secondary'} className="text-xs">
                              {schedule.is_enabled ? t('BackupsPage.schedules.active') : t('BackupsPage.schedules.paused')}
                            </Badge>
                          </div>
                          {schedule.description && (
                            <p className="text-sm text-muted-foreground">{schedule.description}</p>
                          )}
                          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted-foreground mt-2">
                            {schedule.cron_expression && (
                              <div className="flex items-center gap-1">
                                <Clock className="h-3.5 w-3.5" />
                                <code className="px-1.5 py-0.5 bg-muted rounded text-xs">
                                  {schedule.cron_expression}
                                </code>
                                <span className="text-xs">({getNextCronRun(t, schedule.cron_expression)})</span>
                              </div>
                            )}
                            <div className="flex items-center gap-1">
                              <Database className="h-3.5 w-3.5" />
                              <span>{t('BackupsPage.schedules.keepBackups', { count: schedule.max_backups })}</span>
                            </div>
                            <div className="flex items-center gap-1">
                              <Calendar className="h-3.5 w-3.5" />
                              <span>{t('BackupsPage.schedules.retainDays', { count: schedule.retention_days })}</span>
                            </div>
                            {schedule.is_encrypted && (
                              <div className="flex items-center gap-1 text-green-500">
                                <Shield className="h-3.5 w-3.5" />
                                <span>{t('BackupsPage.common.encrypted')}</span>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-3">
                        <div className="text-right">
                          <div className="text-xs text-muted-foreground">{t('BackupsPage.schedules.lastRun')}</div>
                          <div className="text-sm font-medium text-foreground">
                            {formatRelativeTime(t, schedule.last_run_at)}
                          </div>
                          {schedule.next_run_at && (
                            <>
                              <div className="text-xs text-muted-foreground mt-1">{t('BackupsPage.schedules.nextRun')}</div>
                              <div className="text-xs text-primary">
                                {formatRelativeTime(t, schedule.next_run_at).replace(' ago', '')}
                              </div>
                            </>
                          )}
                        </div>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon" className="h-8 w-8">
                              <MoreVertical className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem
                              onClick={() => toggleScheduleMutation.mutate({ id: schedule.id, is_enabled: !schedule.is_enabled })}
                            >
                              {schedule.is_enabled ? (
                                <>
                                  <Pause className="h-4 w-4 mr-2" />
                                  {t('BackupsPage.actions.pauseSchedule')}
                                </>
                              ) : (
                                <>
                                  <Play className="h-4 w-4 mr-2" />
                                  {t('BackupsPage.actions.resumeSchedule')}
                                </>
                              )}
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => handleEditSchedule(schedule)}>
                              <Settings2 className="h-4 w-4 mr-2" />
                              {t('BackupsPage.actions.editSchedule')}
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              onClick={() => {
                                // Create an immediate backup using the schedule's settings
                                const submitData: any = {
                                  name: t('BackupsPage.schedules.manualRunName', { name: schedule.name }),
                                  description: t('BackupsPage.schedules.manualRunDescription', { name: schedule.name }),
                                  backup_type: schedule.backup_type,
                                  site_id: schedule.site_id || null,
                                  device_ids: schedule.device_ids || [],
                                  include_devices: schedule.include_devices,
                                  include_vlans: schedule.include_vlans,
                                  include_ssids: schedule.include_ssids,
                                  include_users: schedule.include_users,
                                  include_automation: schedule.include_automation,
                                  storage_type: schedule.storage_type,
                                  storage_location_id: schedule.storage_location_id || null,
                                  is_encrypted: schedule.is_encrypted,
                                  retention_days: schedule.retention_days,
                                };
                                createMutation.mutate(submitData);
                              }}
                            >
                              <RefreshCw className="h-4 w-4 mr-2" />
                              {t('BackupsPage.actions.runNow')}
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              className="text-destructive"
                              onClick={() => setDeleteScheduleId(schedule.id)}
                            >
                              <Trash2 className="h-4 w-4 mr-2" />
                              {t('BackupsPage.actions.deleteSchedule')}
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
                </div>
              ),
            },
            {
              value: 'history',
              label: t('BackupsPage.tabs.history'),
              content: (
                <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-medium text-foreground">{t('BackupsPage.history.heading')}</h3>
                <p className="text-sm text-muted-foreground">{t('BackupsPage.history.subheading')}</p>
              </div>
            </div>

            {completedBackups.length === 0 ? (
              <EmptyState
                icon={History}
                title={t('BackupsPage.empty.noHistory.title')}
                description={t('BackupsPage.empty.noHistory.description')}
                variant="card"
              />
            ) : (
              <div className="bg-card border border-border rounded-lg divide-y divide-border">
                {backups.map((backup: Backup, index: number) => (
                  <div key={backup.id} className="p-4 hover:bg-muted/50 transition-colors">
                    <div className="flex items-center gap-4">
                      {/* Timeline indicator · uses semantic backup status tone */}
                      <div className="flex flex-col items-center">
                        <div className={cn(
                          'h-3 w-3 rounded-full',
                          backup.status === 'completed' && 'bg-success',
                          backup.status === 'failed' && 'bg-destructive',
                          backup.status === 'in_progress' && 'bg-info',
                          backup.status === 'pending' && 'bg-warning',
                          (backup.status === 'cancelled' || !backup.status) && 'bg-muted',
                        )} />
                        {index < backups.length - 1 && (
                          <div className="w-0.5 h-12 bg-border mt-1" />
                        )}
                      </div>

                      {/* Backup info */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-foreground truncate">{backup.name}</span>
                          <StatusBadge variant={BACKUP_STATUS_VARIANT[backup.status] || 'neutral'} size="sm">
                            {statusLabel(backup.status)}
                          </StatusBadge>
                          {backup.schedule_id && (
                            <Badge variant="outline" className="text-xs">
                              <Timer className="h-3 w-3 mr-1" />
                              {t('BackupsPage.history.scheduled')}
                            </Badge>
                          )}
                        </div>
                        <div className="flex items-center gap-3 text-sm text-muted-foreground mt-1">
                          <span>{formatDate(backup.created_at)}</span>
                          {backup.file_size && (
                            <>
                              <span>•</span>
                              <span>{formatBytes(backup.file_size)}</span>
                            </>
                          )}
                          {backup.is_encrypted && (
                            <>
                              <span>•</span>
                              <span className="flex items-center gap-1 text-green-500">
                                <Shield className="h-3 w-3" />
                                {t('BackupsPage.common.encrypted')}
                              </span>
                            </>
                          )}
                        </div>
                        {backup.error_message && (
                          <p className="text-sm text-destructive mt-1 truncate">{backup.error_message}</p>
                        )}
                      </div>
                      
                      {/* Actions */}
                      {backup.status === 'completed' && (
                        <div className="flex items-center gap-2">
                          <Button 
                            variant="ghost" 
                            size="sm"
                            onClick={() => downloadBackupMutation.mutate(backup)}
                          >
                            <Download className="h-4 w-4" />
                          </Button>
                          <Button 
                            variant="ghost" 
                            size="sm"
                            onClick={() => {
                              setRestoreDialogBackup(backup);
                              setRestoreOptions(defaultRestoreOptions);
                              setRestoreConfirmText('');
                            }}
                          >
                            <RotateCcw className="h-4 w-4" />
                          </Button>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
                </div>
              ),
            },
          ] satisfies PageTab[]}
        />

        {/* Create Backup Dialog · built on FormDialog */}
        <FormDialog<BackupFormSchemaValues>
          open={isDialogOpen}
          onOpenChange={setIsDialogOpen}
          title={t('BackupsPage.createDialog.title')}
          description={t('BackupsPage.createDialog.description')}
          schema={backupFormSchema}
          defaultValues={defaultFormData}
          submitLabel={t('BackupsPage.actions.createBackup')}
          contentClassName="max-w-2xl"
          onSubmit={async (values) => {
            // Parse storage type · may carry a "location:<uuid>" prefix that
            // points to a configured StorageLocation row. In that case we
            // resolve the underlying type from the location.
            let storageType = values.storage_type;
            let storageLocationId: string | null = null;
            if (values.storage_type.startsWith('location:')) {
              storageLocationId = values.storage_type.replace('location:', '');
              const location = storageLocations?.find((loc: any) => loc.id === storageLocationId);
              storageType = location?.storage_type || 'local';
            }

            const submitData = {
              name: values.name,
              description: values.description || null,
              backup_type: values.backup_type,
              site_id: values.site_id === 'all' ? null : values.site_id || null,
              include_devices: values.include_devices,
              include_vlans: values.include_vlans,
              include_ssids: values.include_ssids,
              include_users: values.include_users,
              include_automation: values.include_automation,
              storage_type: storageType,
              storage_location_id: storageLocationId,
              is_encrypted: values.is_encrypted,
              include_secrets: values.include_secrets,
              passphrase: values.include_secrets ? values.passphrase : undefined,
              retention_days: values.retention_days,
            };
            await createMutation.mutateAsync(submitData as any);
          }}
        >
          {(form) => (
            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="name"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('BackupsPage.createDialog.nameLabel')}</FormLabel>
                    <FormControl>
                      <Input placeholder={t('BackupsPage.createDialog.namePlaceholder')} {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="backup_type"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('BackupsPage.createDialog.backupTypeLabel')}</FormLabel>
                    <Select value={field.value} onValueChange={field.onChange}>
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        <SelectItem value="full">{t('BackupsPage.backupTypeOptions.full')}</SelectItem>
                        <SelectItem value="device_config">{t('BackupsPage.backupTypeOptions.deviceConfig')}</SelectItem>
                        <SelectItem value="site_config">{t('BackupsPage.backupTypeOptions.siteConfig')}</SelectItem>
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <div className="col-span-2">
                <FormField
                  control={form.control}
                  name="description"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t('BackupsPage.createDialog.descriptionLabel')}</FormLabel>
                      <FormControl>
                        <Input placeholder={t('BackupsPage.createDialog.descriptionPlaceholder')} {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              <FormField
                control={form.control}
                name="site_id"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('BackupsPage.createDialog.siteLabel')}</FormLabel>
                    <Select value={field.value} onValueChange={field.onChange}>
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue placeholder={t('BackupsPage.createDialog.allSites')} />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        <SelectItem value="all">{t('BackupsPage.createDialog.allSites')}</SelectItem>
                        {sites.map((site: any) => (
                          <SelectItem key={site.id} value={site.id}>
                            {site.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="storage_type"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('BackupsPage.createDialog.storageLabel')}</FormLabel>
                    <Select value={field.value} onValueChange={field.onChange}>
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        <SelectItem value="local">
                          <div className="flex items-center gap-2">
                            <HardDrive className="h-4 w-4" />
                            {t('BackupsPage.storageOptions.local')}
                          </div>
                        </SelectItem>
                        <SelectItem value="s3">
                          <div className="flex items-center gap-2">
                            <Cloud className="h-4 w-4" />
                            {t('BackupsPage.storageOptions.s3')}
                          </div>
                        </SelectItem>
                        <SelectItem value="sftp">
                          <div className="flex items-center gap-2">
                            <Server className="h-4 w-4" />
                            {t('BackupsPage.storageOptions.sftp')}
                          </div>
                        </SelectItem>
                        <SelectItem value="ftp">
                          <div className="flex items-center gap-2">
                            <FolderSync className="h-4 w-4" />
                            {t('BackupsPage.storageOptions.ftp')}
                          </div>
                        </SelectItem>
                        <SelectItem value="google_drive">
                          <div className="flex items-center gap-2">
                            <Cloud className="h-4 w-4" />
                            {t('BackupsPage.storageOptions.googleDrive')}
                          </div>
                        </SelectItem>
                        <SelectItem value="dropbox">
                          <div className="flex items-center gap-2">
                            <Cloud className="h-4 w-4" />
                            {t('BackupsPage.storageOptions.dropbox')}
                          </div>
                        </SelectItem>
                        <SelectItem value="webdav">
                          <div className="flex items-center gap-2">
                            <Cloud className="h-4 w-4" />
                            {t('BackupsPage.storageOptions.webdav')}
                          </div>
                        </SelectItem>
                        {storageLocations && storageLocations.length > 0 && (
                          <>
                            <div className="my-2 border-t" />
                            <div className="px-2 py-1 text-xs text-muted-foreground font-medium">
                              {t('BackupsPage.storageOptions.configuredLocations')}
                            </div>
                            {storageLocations.filter((loc: any) => loc.is_active).map((loc: any) => (
                              <SelectItem key={loc.id} value={`location:${loc.id}`}>
                                <div className="flex items-center gap-2">
                                  {storageIcons[loc.storage_type] || <Archive className="h-4 w-4" />}
                                  {loc.name}
                                  {loc.is_default && (
                                    <span className="text-xs bg-primary/10 text-primary px-1.5 py-0.5 rounded">
                                      {t('BackupsPage.storageOptions.default')}
                                    </span>
                                  )}
                                </div>
                              </SelectItem>
                            ))}
                          </>
                        )}
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground">
                      <Link to="/backups/storage-locations" className="text-primary hover:underline">{t('BackupsPage.createDialog.manageStorageLink')}</Link>
                    </p>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="retention_days"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('BackupsPage.createDialog.retentionLabel')}</FormLabel>
                    <FormControl>
                      <Input type="number" min={1} max={365} {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="is_encrypted"
                render={({ field }) => (
                  <FormItem>
                    <div className="flex items-center justify-between py-2">
                      <div>
                        <FormLabel>{t('BackupsPage.createDialog.encryptionLabel')}</FormLabel>
                        <p className="text-sm text-muted-foreground">{t('BackupsPage.createDialog.encryptionHelp')}</p>
                      </div>
                      <FormControl>
                        <Switch checked={field.value} onCheckedChange={field.onChange} />
                      </FormControl>
                    </div>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {/* Full ("vault") backup: include ALL secrets, sealed under an operator
                  passphrase. Off = the secret-free config snapshot (.fsdn). */}
              <FormField
                control={form.control}
                name="include_secrets"
                render={({ field }) => (
                  <FormItem>
                    <div className="flex items-center justify-between py-2">
                      <div>
                        <FormLabel>{t('BackupsPage.createDialog.fullBackupLabel')}</FormLabel>
                        <p className="text-sm text-muted-foreground">{t('BackupsPage.createDialog.fullBackupHelp')}</p>
                      </div>
                      <FormControl>
                        <Switch checked={field.value} onCheckedChange={field.onChange} />
                      </FormControl>
                    </div>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {form.watch('include_secrets') && (
                <div className="col-span-2 space-y-3">
                  <div className="bg-destructive/10 border border-destructive/30 rounded-lg p-3 flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-destructive mt-0.5 shrink-0" />
                    <div className="text-sm text-destructive">
                      <strong>{t('BackupsPage.createDialog.fullBackupWarnLabel')}</strong>{' '}
                      {t('BackupsPage.createDialog.fullBackupWarnText')}
                    </div>
                  </div>
                  <FormField
                    control={form.control}
                    name="passphrase"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>{t('BackupsPage.createDialog.passphraseLabel')}</FormLabel>
                        <FormControl>
                          <Input
                            type="password"
                            autoComplete="new-password"
                            placeholder={t('BackupsPage.createDialog.passphrasePlaceholder')}
                            {...field}
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>
              )}

              <div className="col-span-2 border border-border rounded-lg p-4">
                <Label className="mb-3 block">{t('BackupsPage.include.title')}</Label>
                <div className="grid grid-cols-2 gap-4">
                  <FormField
                    control={form.control}
                    name="include_devices"
                    render={({ field }) => (
                      <div className="flex items-center justify-between">
                        <span className="text-sm">{t('BackupsPage.include.devices')}</span>
                        <Switch checked={field.value} onCheckedChange={field.onChange} />
                      </div>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="include_vlans"
                    render={({ field }) => (
                      <div className="flex items-center justify-between">
                        <span className="text-sm">{t('BackupsPage.include.vlans')}</span>
                        <Switch checked={field.value} onCheckedChange={field.onChange} />
                      </div>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="include_ssids"
                    render={({ field }) => (
                      <div className="flex items-center justify-between">
                        <span className="text-sm">{t('BackupsPage.include.ssids')}</span>
                        <Switch checked={field.value} onCheckedChange={field.onChange} />
                      </div>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="include_users"
                    render={({ field }) => (
                      <div className="flex items-center justify-between">
                        <span className="text-sm">{t('BackupsPage.include.users')}</span>
                        <Switch checked={field.value} onCheckedChange={field.onChange} />
                      </div>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="include_automation"
                    render={({ field }) => (
                      <div className="flex items-center justify-between">
                        <span className="text-sm">{t('BackupsPage.include.automation')}</span>
                        <Switch checked={field.value} onCheckedChange={field.onChange} />
                      </div>
                    )}
                  />
                </div>
              </div>
            </div>
          )}
        </FormDialog>

        {/* Delete Confirmation Dialog */}
        <Dialog
          open={!!deleteConfirmId}
          onOpenChange={() => setDeleteConfirmId(null)}
        >
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{t('BackupsPage.deleteDialog.title')}</DialogTitle>
              <DialogDescription>
                {t('BackupsPage.deleteDialog.description')}
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="outline" onClick={() => setDeleteConfirmId(null)}>
                {t('BackupsPage.actions.cancel')}
              </Button>
              <Button
                variant="destructive"
                onClick={() => deleteConfirmId && deleteMutation.mutate(deleteConfirmId)}
                disabled={deleteMutation.isPending}
              >
                {t('BackupsPage.actions.deleteBackup')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Enhanced Restore Dialog */}
        <Dialog
          open={!!restoreDialogBackup}
          onOpenChange={() => {
            setRestoreDialogBackup(null);
            setRestoreOptions(defaultRestoreOptions);
            setRestoreConfirmText('');
            setDryRunResult(null);
          }}
        >
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <RotateCcw className="h-5 w-5" />
                {t('BackupsPage.restoreDialog.title')}
              </DialogTitle>
              <DialogDescription>
                {t('BackupsPage.restoreDialog.description', { name: restoreDialogBackup?.name ?? '' })}
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-4 py-4">
              {/* Backup Info */}
              <div className="bg-muted/50 rounded-lg p-4 space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">{t('BackupsPage.restoreDialog.created')}</span>
                  <span className="font-medium">{formatDate(restoreDialogBackup?.created_at || null)}</span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">{t('BackupsPage.restoreDialog.size')}</span>
                  <span className="font-medium">{formatBytes(restoreDialogBackup?.file_size || null)}</span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">{t('BackupsPage.restoreDialog.type')}</span>
                  <Badge variant="outline">{humanizeBackupType(t, restoreDialogBackup?.backup_type)}</Badge>
                </div>
                {restoreDialogBackup?.is_encrypted && (
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">{t('BackupsPage.restoreDialog.security')}</span>
                    <span className="flex items-center gap-1 text-green-500">
                      <Shield className="h-3.5 w-3.5" />
                      {t('BackupsPage.common.encrypted')}
                    </span>
                  </div>
                )}
              </div>

              {/* Modules to restore (enterprise backup v2, selective
                  restore). Reads the backup's manifest and lets the
                  operator pick which contributors to apply. Incompatible
                  sections (schema major mismatch / module not installed)
                  are shown but disabled. */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <Label className="text-base">{t('BackupsPage.restoreDialog.modulesTitle')}</Label>
                  {restoreManifest && (
                    <span className="text-xs text-muted-foreground">
                      {selectedContributors === null
                        ? t('BackupsPage.restoreDialog.allModules')
                        : t('BackupsPage.restoreDialog.selectedCount', {
                            selected: selectedContributors.size,
                            total: restoreManifest.contributors.length,
                          })}
                    </span>
                  )}
                </div>

                {manifestLoading && (
                  <div className="flex items-center gap-2 text-sm text-muted-foreground p-3">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    {t('BackupsPage.restoreDialog.readingManifest')}
                  </div>
                )}

                {manifestError && (
                  <div className="bg-muted/30 rounded-lg p-3 text-sm text-muted-foreground">
                    {t('BackupsPage.restoreDialog.manifestError')}
                  </div>
                )}

                {restoreManifest && (() => {
                  const restorableIds = restoreManifest.contributors
                    .filter((c) => c.restorable)
                    .map((c) => c.id);
                  return (
                    <div className="space-y-2">
                      {restoreManifest.contributors.map((c) => {
                        const totalRows = Object.values(c.counts).reduce((a, b) => a + b, 0);
                        return (
                          <div
                            key={c.id}
                            className={`flex items-start justify-between p-3 rounded-lg border ${
                              c.restorable
                                ? 'bg-muted/30 border-border'
                                : 'bg-muted/10 border-dashed border-border/60 opacity-70'
                            }`}
                          >
                            <div className="flex items-start gap-3">
                              <Checkbox
                                checked={c.restorable && isContributorChecked(c.id)}
                                disabled={!c.restorable}
                                onCheckedChange={() => toggleContributor(c.id, restorableIds)}
                                className="mt-0.5"
                                aria-label={t('BackupsPage.restoreDialog.restoreModuleAria', { module: c.id })}
                              />
                              <div>
                                <div className="text-sm font-medium capitalize flex items-center gap-2">
                                  {c.id}
                                  <Badge variant="outline" className="text-[10px]">
                                    {t('BackupsPage.restoreDialog.schemaBadge', { version: c.schema_version })}
                                  </Badge>
                                </div>
                                <p className="text-xs text-muted-foreground">
                                  {t('BackupsPage.restoreDialog.itemCount', { count: totalRows })}
                                  {Object.keys(c.counts).length > 0 && (
                                    <span className="ml-1">
                                      ({Object.entries(c.counts)
                                        .map(([k, v]) => `${v} ${k}`)
                                        .join(', ')})
                                    </span>
                                  )}
                                </p>
                                {!c.restorable && c.incompatibility_reason && (
                                  <p className="text-xs text-yellow-500 mt-1 flex items-start gap-1">
                                    <AlertTriangle className="h-3 w-3 mt-0.5 shrink-0" />
                                    {c.incompatibility_reason}
                                  </p>
                                )}
                              </div>
                            </div>
                          </div>
                        );
                      })}
                      {restorableIds.length === 0 && (
                        <div className="text-xs text-yellow-500 p-2">
                          {t('BackupsPage.restoreDialog.noRestorableModules')}
                        </div>
                      )}
                    </div>
                  );
                })()}
              </div>

              {/* What to Restore (legacy per-category toggles, these map
                  to the ``core`` contributor's restore options). */}
              <div className="space-y-3">
                <Label className="text-base">{t('BackupsPage.restoreDialog.whatToRestore')}</Label>
                <div className="grid grid-cols-2 gap-3">
                  <div className="flex items-center justify-between p-3 bg-muted/30 rounded-lg">
                    <div className="flex items-center gap-2">
                      <Server className="h-4 w-4 text-muted-foreground" />
                      <span className="text-sm">{t('BackupsPage.include.devices')}</span>
                    </div>
                    <Switch
                      checked={restoreOptions.restore_devices}
                      onCheckedChange={(checked) =>
                        updateRestoreOption({ restore_devices: checked })
                      }
                    />
                  </div>
                  <div className="flex items-center justify-between p-3 bg-muted/30 rounded-lg">
                    <div className="flex items-center gap-2">
                      <Database className="h-4 w-4 text-muted-foreground" />
                      <span className="text-sm">{t('BackupsPage.include.vlans')}</span>
                    </div>
                    <Switch
                      checked={restoreOptions.restore_vlans}
                      onCheckedChange={(checked) =>
                        updateRestoreOption({ restore_vlans: checked })
                      }
                    />
                  </div>
                  <div className="flex items-center justify-between p-3 bg-muted/30 rounded-lg">
                    <div className="flex items-center gap-2">
                      <Cloud className="h-4 w-4 text-muted-foreground" />
                      <span className="text-sm">{t('BackupsPage.include.ssids')}</span>
                    </div>
                    <Switch
                      checked={restoreOptions.restore_ssids}
                      onCheckedChange={(checked) =>
                        updateRestoreOption({ restore_ssids: checked })
                      }
                    />
                  </div>
                  <div className="flex items-center justify-between p-3 bg-muted/30 rounded-lg">
                    <div className="flex items-center gap-2">
                      <Settings2 className="h-4 w-4 text-muted-foreground" />
                      <span className="text-sm">{t('BackupsPage.include.automation')}</span>
                    </div>
                    <Switch
                      checked={restoreOptions.restore_automation}
                      onCheckedChange={(checked) =>
                        updateRestoreOption({ restore_automation: checked })
                      }
                    />
                  </div>
                </div>
              </div>

              {/* Restore Options */}
              <div className="space-y-3">
                <Label className="text-base">{t('BackupsPage.restoreDialog.options')}</Label>
                <div className="space-y-2">
                  <div className="flex items-center justify-between p-3 bg-muted/30 rounded-lg">
                    <div>
                      <span className="text-sm font-medium">{t('BackupsPage.restoreDialog.overwriteTitle')}</span>
                      <p className="text-xs text-muted-foreground">{t('BackupsPage.restoreDialog.overwriteHelp')}</p>
                    </div>
                    <Switch
                      checked={restoreOptions.overwrite_existing}
                      onCheckedChange={(checked) =>
                        updateRestoreOption({ overwrite_existing: checked })
                      }
                    />
                  </div>
                </div>
              </div>

              {/* Warning */}
              <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-3 flex items-start gap-2">
                <AlertTriangle className="h-4 w-4 text-yellow-500 mt-0.5 shrink-0" />
                <div className="text-sm text-yellow-400">
                  <strong>{t('BackupsPage.restoreDialog.warningLabel')}</strong> {t('BackupsPage.restoreDialog.warningText')}
                </div>
              </div>

              {/* Honesty: a config snapshot carries NO secrets — tell the operator
                  they must re-enter credentials for any restored controllers/devices
                  and point to pg-backup for full DR (mirrors the page banner). */}
              <div className="bg-info/10 border border-info/20 rounded-lg p-3 flex items-start gap-2">
                <Info className="h-4 w-4 text-info mt-0.5 shrink-0" />
                <div className="text-sm text-info">
                  <strong>{t('BackupsPage.restoreDialog.credentialNoteLabel')}</strong>{' '}
                  {t('BackupsPage.restoreDialog.credentialNoteText')}
                </div>
              </div>

              {/* Dry-run preview result, populated by "Preview Changes".
                  Renders the per-contributor would-create / would-update /
                  would-skip counts so the dry run is actually reviewable
                  (previously the result was discarded and the dialog just
                  closed with a vague toast). */}
              {dryRunResult && (
                <div className="rounded-lg border border-info/30 bg-info/5 p-3 space-y-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 text-sm font-medium text-foreground">
                      <Eye className="h-4 w-4 text-info" />
                      {t('BackupsPage.dryRun.header')}
                    </div>
                    <div className="flex items-center gap-3 text-xs">
                      <span className="text-success">{t('BackupsPage.dryRun.createCount', { count: dryRunResult.summary.total_created })}</span>
                      <span className="text-info">{t('BackupsPage.dryRun.updateCount', { count: dryRunResult.summary.total_updated })}</span>
                      <span className="text-muted-foreground">{t('BackupsPage.dryRun.skipCount', { count: dryRunResult.summary.total_skipped })}</span>
                      {dryRunResult.summary.total_errors > 0 && (
                        <span className="text-destructive">{t('BackupsPage.dryRun.errorCount', { count: dryRunResult.summary.total_errors })}</span>
                      )}
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    {dryRunResult.contributors.map((c) => {
                      const sum = (o: Record<string, number>) =>
                        Object.values(o ?? {}).reduce((a, b) => a + b, 0);
                      const created = sum(c.created);
                      const updated = sum(c.updated);
                      const skipped = sum(c.skipped);
                      const failed = c.status === 'error' || c.status === 'schema_mismatch';
                      return (
                        <div
                          key={c.contributor_id}
                          className="flex items-center justify-between gap-2 rounded bg-background/40 px-2.5 py-1.5 text-xs"
                        >
                          <div className="flex items-center gap-2">
                            {failed ? (
                              <XCircle className="h-3.5 w-3.5 text-destructive shrink-0" />
                            ) : (
                              <CheckCircle className="h-3.5 w-3.5 text-success shrink-0" />
                            )}
                            <span className="font-medium capitalize">{c.contributor_id}</span>
                          </div>
                          <div className="flex items-center gap-3 text-right">
                            {created > 0 && <span className="text-success">+{created}</span>}
                            {updated > 0 && <span className="text-info">~{updated}</span>}
                            {skipped > 0 && (
                              <span className="text-muted-foreground">{t('BackupsPage.dryRun.skippedSuffix', { count: skipped })}</span>
                            )}
                            {created === 0 && updated === 0 && skipped === 0 && !failed && (
                              <span className="text-muted-foreground">{t('BackupsPage.dryRun.noChanges')}</span>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                  {/* Surface per-contributor errors + warnings (e.g.
                      cross-tenant rejects) so the operator sees them
                      before committing. */}
                  {dryRunResult.contributors.some(
                    (c) => c.warnings?.length || c.errors?.length,
                  ) && (
                    <div className="space-y-1 border-t border-border/50 pt-2">
                      {dryRunResult.contributors
                        .flatMap((c) => [
                          ...(c.errors ?? []).map((msg) => ({
                            kind: 'error' as const,
                            cid: c.contributor_id,
                            msg,
                          })),
                          ...(c.warnings ?? []).map((msg) => ({
                            kind: 'warn' as const,
                            cid: c.contributor_id,
                            msg,
                          })),
                        ])
                        .map((item, i) => (
                          <p
                            key={`${item.cid}-${i}`}
                            className={cn(
                              'flex items-start gap-1 text-xs',
                              item.kind === 'error' ? 'text-destructive' : 'text-yellow-500',
                            )}
                          >
                            <AlertTriangle className="h-3 w-3 mt-0.5 shrink-0" />
                            <span>
                              <span className="font-medium capitalize">{item.cid}:</span>{' '}
                              {item.msg}
                            </span>
                          </p>
                        ))}
                    </div>
                  )}
                </div>
              )}

              {/* Full (.fsdnvault) backup: the operator passphrase is required to
                  decrypt + re-key it onto this instance. */}
              {restoreDialogBackup?.include_secrets && (
                <div className="space-y-2">
                  <Label htmlFor="restore-passphrase" className="text-sm">
                    {t('BackupsPage.restoreDialog.passphraseLabel')}
                  </Label>
                  <Input
                    id="restore-passphrase"
                    type="password"
                    autoComplete="off"
                    value={restoreOptions.passphrase}
                    onChange={(e) =>
                      setRestoreOptions((o) => ({ ...o, passphrase: e.target.value }))
                    }
                    placeholder={t('BackupsPage.restoreDialog.passphrasePlaceholder')}
                  />
                </div>
              )}

              {/* typed confirmation, must match backup name or "RESTORE". */}
              <div className="space-y-2">
                <Label htmlFor="restore-confirm" className="text-sm">
                  {t('BackupsPage.restoreDialog.confirmTypePrefix')}{' '}
                  <span className="font-mono font-semibold">
                    {restoreDialogBackup?.name || 'RESTORE'}
                  </span>{' '}
                  {t('BackupsPage.restoreDialog.confirmTypeOr')}{' '}
                  <span className="font-mono font-semibold">RESTORE</span>{' '}
                  {t('BackupsPage.restoreDialog.confirmTypeSuffix')}
                </Label>
                <Input
                  id="restore-confirm"
                  value={restoreConfirmText}
                  onChange={(e) => setRestoreConfirmText(e.target.value)}
                  placeholder={t('BackupsPage.restoreDialog.confirmPlaceholder')}
                  autoComplete="off"
                />
              </div>
            </div>

            <DialogFooter className="gap-2">
              <Button 
                variant="outline" 
                onClick={() => {
                  setRestoreDialogBackup(null);
                  setRestoreOptions(defaultRestoreOptions);
                  setRestoreConfirmText('');
                }}
              >
                {t('BackupsPage.actions.cancel')}
              </Button>
              <Button
                variant="outline"
                onClick={() => {
                  if (!restoreDialogBackup) return;
                  restoreMutation.mutate({
                    backup_id: restoreDialogBackup.id,
                    ...restoreOptions,
                    contributors: restoreContributorSelection(),
                    dry_run: true,
                  });
                }}
                disabled={restoreMutation.isPending}
                className="gap-2"
              >
                <Eye className="h-4 w-4" />
                {t('BackupsPage.actions.previewChanges')}
              </Button>
              <Button
                onClick={() => {
                  if (!restoreDialogBackup) return;
                  restoreMutation.mutate({
                    backup_id: restoreDialogBackup.id,
                    ...restoreOptions,
                    contributors: restoreContributorSelection(),
                    dry_run: false,
                  });
                }}
                disabled={
                  restoreMutation.isPending ||
                  // require typed confirmation. Accept either the
                  // exact backup name OR the sentinel "RESTORE".
                  (restoreConfirmText !== 'RESTORE' &&
                    restoreConfirmText !== (restoreDialogBackup?.name ?? ''))
                }
                className="gap-2"
              >
                {restoreMutation.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <RotateCcw className="h-4 w-4" />
                )}
                {t('BackupsPage.actions.restoreNow')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Schedule Create/Edit Dialog */}
        <Dialog
          open={isScheduleDialogOpen}
          onOpenChange={(open) => {
            if (!open) {
              setIsScheduleDialogOpen(false);
              setEditingSchedule(null);
              resetScheduleForm();
            }
          }}
        >
          <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Calendar className="h-5 w-5" />
                {editingSchedule ? t('BackupsPage.scheduleDialog.editTitle') : t('BackupsPage.scheduleDialog.createTitle')}
              </DialogTitle>
              <DialogDescription>
                {t('BackupsPage.scheduleDialog.description')}
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-6 py-4">
              {/* Basic Info */}
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="schedule-name">{t('BackupsPage.scheduleDialog.nameLabel')}</Label>
                  <Input
                    id="schedule-name"
                    value={scheduleFormData.name}
                    onChange={(e) => setScheduleFormData({ ...scheduleFormData, name: e.target.value })}
                    placeholder={t('BackupsPage.scheduleDialog.namePlaceholder')}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="schedule-type">{t('BackupsPage.createDialog.backupTypeLabel')}</Label>
                  <Select
                    value={scheduleFormData.backup_type}
                    onValueChange={(value) => setScheduleFormData({ ...scheduleFormData, backup_type: value })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="full">{t('BackupsPage.backupTypeOptions.full')}</SelectItem>
                      <SelectItem value="device_config">{t('BackupsPage.backupTypeOptions.deviceConfig')}</SelectItem>
                      <SelectItem value="site_config">{t('BackupsPage.backupTypeOptions.siteConfig')}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="schedule-description">{t('BackupsPage.scheduleDialog.descriptionLabel')}</Label>
                <Input
                  id="schedule-description"
                  value={scheduleFormData.description}
                  onChange={(e) => setScheduleFormData({ ...scheduleFormData, description: e.target.value })}
                  placeholder={t('BackupsPage.scheduleDialog.descriptionPlaceholder')}
                />
              </div>

              {/* Schedule Configuration */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <Label className="text-base">{t('BackupsPage.scheduleDialog.scheduleLabel')}</Label>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setShowCronHelp(!showCronHelp)}
                    className="gap-1 text-xs"
                  >
                    <Info className="h-3.5 w-3.5" />
                    {showCronHelp ? t('BackupsPage.scheduleDialog.hideHelp') : t('BackupsPage.scheduleDialog.showHelp')}
                  </Button>
                </div>

                {showCronHelp && (
                  <div className="bg-muted/50 rounded-lg p-3 text-sm space-y-2">
                    <p className="text-muted-foreground">
                      <strong>{t('BackupsPage.scheduleDialog.cronFormatLabel')}</strong> {t('BackupsPage.scheduleDialog.cronFormatValue')}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {t('BackupsPage.scheduleDialog.cronExampleLabel')} <code className="bg-muted px-1 rounded">0 2 * * *</code> {t('BackupsPage.scheduleDialog.cronExampleValue')}
                    </p>
                  </div>
                )}

                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>{t('BackupsPage.scheduleDialog.quickPresets')}</Label>
                    <Select
                      value=""
                      onValueChange={(value) => setScheduleFormData({ ...scheduleFormData, cron_expression: value })}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder={t('BackupsPage.scheduleDialog.selectPreset')} />
                      </SelectTrigger>
                      <SelectContent>
                        {cronPresets.map((preset) => (
                          <SelectItem key={preset.value} value={preset.value}>
                            <div className="flex flex-col">
                              <span>{t(`BackupsPage.cronPresets.${preset.labelKey}.label`)}</span>
                              <span className="text-xs text-muted-foreground">{t(`BackupsPage.cronPresets.${preset.descKey}.description`)}</span>
                            </div>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="cron-expression">{t('BackupsPage.scheduleDialog.cronExpressionLabel')}</Label>
                    <Input
                      id="cron-expression"
                      value={scheduleFormData.cron_expression}
                      onChange={(e) => setScheduleFormData({ ...scheduleFormData, cron_expression: e.target.value })}
                      placeholder="0 2 * * *"
                      className="font-mono"
                    />
                    <p className="text-xs text-muted-foreground">
                      {getNextCronRun(t, scheduleFormData.cron_expression)}
                    </p>
                  </div>
                </div>

                <div className="space-y-2">
                  <Label>{t('BackupsPage.scheduleDialog.timezone')}</Label>
                  <Select
                    value={scheduleFormData.timezone}
                    onValueChange={(value) => setScheduleFormData({ ...scheduleFormData, timezone: value })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="UTC">UTC</SelectItem>
                      <SelectItem value="America/New_York">{t('BackupsPage.timezones.easternUs')}</SelectItem>
                      <SelectItem value="America/Chicago">{t('BackupsPage.timezones.centralUs')}</SelectItem>
                      <SelectItem value="America/Denver">{t('BackupsPage.timezones.mountainUs')}</SelectItem>
                      <SelectItem value="America/Los_Angeles">{t('BackupsPage.timezones.pacificUs')}</SelectItem>
                      <SelectItem value="Europe/London">{t('BackupsPage.timezones.londonUk')}</SelectItem>
                      <SelectItem value="Europe/Paris">{t('BackupsPage.timezones.parisEu')}</SelectItem>
                      <SelectItem value="Asia/Tokyo">{t('BackupsPage.timezones.tokyoJapan')}</SelectItem>
                      <SelectItem value="Australia/Sydney">{t('BackupsPage.timezones.sydneyAustralia')}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {/* Retention Policy */}
              <div className="space-y-3">
                <Label className="text-base">{t('BackupsPage.scheduleDialog.retentionPolicy')}</Label>
                <div className="bg-muted/30 rounded-lg p-4 space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="max-backups" className="flex items-center gap-2">
                        <Database className="h-4 w-4" />
                        {t('BackupsPage.scheduleDialog.maxBackupsLabel')}
                      </Label>
                      <Input
                        id="max-backups"
                        type="number"
                        min={1}
                        max={100}
                        value={scheduleFormData.max_backups}
                        onChange={(e) => setScheduleFormData({
                          ...scheduleFormData,
                          max_backups: parseInt(e.target.value) || 7
                        })}
                      />
                      <p className="text-xs text-muted-foreground">
                        {t('BackupsPage.scheduleDialog.maxBackupsHelp', { count: scheduleFormData.max_backups })}
                      </p>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="retention-days" className="flex items-center gap-2">
                        <Calendar className="h-4 w-4" />
                        {t('BackupsPage.scheduleDialog.retentionDaysLabel')}
                      </Label>
                      <Input
                        id="retention-days"
                        type="number"
                        min={1}
                        max={365}
                        value={scheduleFormData.retention_days}
                        onChange={(e) => setScheduleFormData({
                          ...scheduleFormData,
                          retention_days: parseInt(e.target.value) || 30
                        })}
                      />
                      <p className="text-xs text-muted-foreground">
                        {t('BackupsPage.scheduleDialog.retentionDaysHelp', { count: scheduleFormData.retention_days })}
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Storage & Security */}
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>{t('BackupsPage.createDialog.storageLabel')}</Label>
                  <Select
                    value={scheduleFormData.storage_type}
                    onValueChange={(value) => setScheduleFormData({ ...scheduleFormData, storage_type: value })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="local">
                        <div className="flex items-center gap-2">
                          <HardDrive className="h-4 w-4" />
                          {t('BackupsPage.storageOptions.local')}
                        </div>
                      </SelectItem>
                      <SelectItem value="s3">
                        <div className="flex items-center gap-2">
                          <Cloud className="h-4 w-4" />
                          {t('BackupsPage.storageOptions.s3Short')}
                        </div>
                      </SelectItem>
                      <SelectItem value="sftp">
                        <div className="flex items-center gap-2">
                          <Server className="h-4 w-4" />
                          {t('BackupsPage.storageOptions.sftp')}
                        </div>
                      </SelectItem>
                      {storageLocations && storageLocations.length > 0 && (
                        <>
                          <div className="my-2 border-t" />
                          <div className="px-2 py-1 text-xs text-muted-foreground font-medium">
                            {t('BackupsPage.storageOptions.configuredLocations')}
                          </div>
                          {storageLocations.filter((loc: any) => loc.is_active).map((loc: any) => (
                            <SelectItem key={loc.id} value={`location:${loc.id}`}>
                              <div className="flex items-center gap-2">
                                {storageIcons[loc.storage_type] || <Archive className="h-4 w-4" />}
                                {loc.name}
                                {loc.is_default && (
                                  <span className="text-xs bg-primary/10 text-primary px-1.5 py-0.5 rounded">
                                    {t('BackupsPage.storageOptions.default')}
                                  </span>
                                )}
                              </div>
                            </SelectItem>
                          ))}
                        </>
                      )}
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex items-center justify-between p-3 bg-muted/30 rounded-lg">
                  <div className="flex items-center gap-2">
                    <Shield className="h-4 w-4 text-green-500" />
                    <div>
                      <span className="text-sm font-medium">{t('BackupsPage.createDialog.encryptionLabel')}</span>
                      <p className="text-xs text-muted-foreground">{t('BackupsPage.scheduleDialog.encryptFilesHelp')}</p>
                    </div>
                  </div>
                  <Switch
                    checked={scheduleFormData.is_encrypted}
                    onCheckedChange={(checked) => setScheduleFormData({ ...scheduleFormData, is_encrypted: checked })}
                  />
                </div>
              </div>

              {/* What to Include */}
              <div className="space-y-3">
                <Label className="text-base">{t('BackupsPage.include.title')}</Label>
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                  {/*
                    "Include VLANs" and "Include SSIDs" were REMOVED here.

                    A backup contains sites, controllers, credentials,
                    automation rules, devices and users -- that is the whole of
                    BackupService's restore_map. It has never contained VLANs
                    or SSIDs. The two flags were threaded through three layers
                    and recorded in the archive's own metadata, and read by
                    nothing: there is no `if include_vlans:` anywhere.

                    So the toggles asked an operator to make a choice that
                    changed nothing, and the archive then claimed to describe
                    its own contents using their answer. On a disaster restore
                    that is the worst possible place to be reassured: someone
                    would reasonably believe their VLANs were in the file.

                    Reinstating them means actually collecting and restoring
                    those rows (with the controller-sync ordering that implies),
                    not re-adding the switches.
                  */}
                  {[
                    { key: 'include_devices', labelKey: 'devices', icon: Server },
                    { key: 'include_users', labelKey: 'users', icon: Shield },
                    { key: 'include_automation', labelKey: 'automation', icon: Settings2 },
                  ].map(({ key, labelKey, icon: Icon }) => (
                    <div key={key} className="flex items-center justify-between p-3 bg-muted/30 rounded-lg">
                      <div className="flex items-center gap-2">
                        <Icon className="h-4 w-4 text-muted-foreground" />
                        <span className="text-sm">{t(`BackupsPage.include.${labelKey}`)}</span>
                      </div>
                      <Switch
                        checked={scheduleFormData[key as keyof ScheduleFormData] as boolean}
                        onCheckedChange={(checked) => setScheduleFormData({ 
                          ...scheduleFormData, 
                          [key]: checked 
                        })}
                      />
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <DialogFooter>
              <Button 
                variant="outline" 
                onClick={() => {
                  setIsScheduleDialogOpen(false);
                  setEditingSchedule(null);
                  resetScheduleForm();
                }}
              >
                {t('BackupsPage.actions.cancel')}
              </Button>
              <Button
                onClick={handleScheduleSubmit}
                disabled={
                  createScheduleMutation.isPending ||
                  updateScheduleMutation.isPending ||
                  !scheduleFormData.name ||
                  !scheduleFormData.cron_expression
                }
                className="gap-2"
              >
                {(createScheduleMutation.isPending || updateScheduleMutation.isPending) ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Calendar className="h-4 w-4" />
                )}
                {editingSchedule ? t('BackupsPage.actions.updateSchedule') : t('BackupsPage.actions.createSchedule')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Delete Schedule Confirmation */}
        <Dialog
          open={!!deleteScheduleId}
          onOpenChange={() => setDeleteScheduleId(null)}
        >
          <DialogContent>
            <DialogHeader>
              <DialogTitle>{t('BackupsPage.deleteScheduleDialog.title')}</DialogTitle>
              <DialogDescription>
                {t('BackupsPage.deleteScheduleDialog.description')}
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="outline" onClick={() => setDeleteScheduleId(null)}>
                {t('BackupsPage.actions.cancel')}
              </Button>
              <Button
                variant="destructive"
                onClick={() => deleteScheduleId && deleteScheduleMutation.mutate(deleteScheduleId)}
                disabled={deleteScheduleMutation.isPending}
              >
                {deleteScheduleMutation.isPending ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Trash2 className="h-4 w-4 mr-2" />
                )}
                {t('BackupsPage.actions.deleteSchedule')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Backup Detail Dialog */}
        <Dialog
          open={!!viewHistoryBackup}
          onOpenChange={() => setViewHistoryBackup(null)}
        >
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <FileJson className="h-5 w-5" />
                {t('BackupsPage.detailDialog.title')}
              </DialogTitle>
            </DialogHeader>
            {viewHistoryBackup && (
              <div className="space-y-4 py-4">
                <div className="space-y-2">
                  <h3 className="font-medium">{viewHistoryBackup.name}</h3>
                  {viewHistoryBackup.description && (
                    <p className="text-sm text-muted-foreground">{viewHistoryBackup.description}</p>
                  )}
                </div>

                <div className="bg-muted/50 rounded-lg p-4 space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">{t('BackupsPage.detailDialog.status')}</span>
                    <StatusBadge variant={BACKUP_STATUS_VARIANT[viewHistoryBackup.status] || 'neutral'}>
                      {statusLabel(viewHistoryBackup.status)}
                    </StatusBadge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">{t('BackupsPage.restoreDialog.created')}</span>
                    <span>{formatDate(viewHistoryBackup.created_at)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">{t('BackupsPage.restoreDialog.size')}</span>
                    <span>{formatBytes(viewHistoryBackup.file_size)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">{t('BackupsPage.restoreDialog.type')}</span>
                    <span>{humanizeBackupType(t, viewHistoryBackup.backup_type)}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">{t('BackupsPage.detailDialog.storage')}</span>
                    <span className="flex items-center gap-1">
                      {storageIcons[viewHistoryBackup.storage_type]}
                      {humanizeStorageType(t, viewHistoryBackup.storage_type)}
                    </span>
                  </div>
                  {viewHistoryBackup.is_encrypted && (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">{t('BackupsPage.common.encrypted')}</span>
                      <span className="text-green-500 flex items-center gap-1">
                        <Shield className="h-3.5 w-3.5" />
                        {t('BackupsPage.detailDialog.yes')}
                      </span>
                    </div>
                  )}
                  {viewHistoryBackup.expires_at && (
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">{t('BackupsPage.detailDialog.expires')}</span>
                      <span>{formatDate(viewHistoryBackup.expires_at)}</span>
                    </div>
                  )}
                </div>

                <div className="space-y-2">
                  <Label className="text-sm">{t('BackupsPage.detailDialog.includedInBackup')}</Label>
                  <div className="flex flex-wrap gap-2">
                    {viewHistoryBackup.include_devices && <Badge variant="secondary">{t('BackupsPage.include.devices')}</Badge>}
                    {viewHistoryBackup.include_vlans && <Badge variant="secondary">{t('BackupsPage.include.vlans')}</Badge>}
                    {viewHistoryBackup.include_ssids && <Badge variant="secondary">{t('BackupsPage.include.ssids')}</Badge>}
                    {viewHistoryBackup.include_users && <Badge variant="secondary">{t('BackupsPage.include.users')}</Badge>}
                    {viewHistoryBackup.include_automation && <Badge variant="secondary">{t('BackupsPage.include.automation')}</Badge>}
                  </div>
                </div>

                {viewHistoryBackup.error_message && (
                  <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-3 text-sm text-destructive">
                    {viewHistoryBackup.error_message}
                  </div>
                )}
              </div>
            )}
            <DialogFooter>
              <Button variant="outline" onClick={() => setViewHistoryBackup(null)}>
                {t('BackupsPage.actions.close')}
              </Button>
              {viewHistoryBackup?.status === 'completed' && (
                <>
                  <Button
                    variant="outline"
                    onClick={() => viewHistoryBackup && downloadBackupMutation.mutate(viewHistoryBackup)}
                    className="gap-2"
                  >
                    <Download className="h-4 w-4" />
                    {t('BackupsPage.actions.download')}
                  </Button>
                  <Button
                    onClick={() => {
                      if (viewHistoryBackup) {
                        setViewHistoryBackup(null);
                        setRestoreDialogBackup(viewHistoryBackup);
                        setRestoreOptions(defaultRestoreOptions);
                        setRestoreConfirmText('');
                      }
                    }}
                    className="gap-2"
                  >
                    <RotateCcw className="h-4 w-4" />
                    {t('BackupsPage.actions.restore')}
                  </Button>
                </>
              )}
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Import Preview Dialog */}
        <Dialog
          open={showImportDialog}
          onOpenChange={(open) => {
            if (!open) {
              setShowImportDialog(false);
              setImportFile(null);
              setImportPreview(null);
            }
          }}
        >
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Upload className="h-5 w-5" />
                {t('BackupsPage.importDialog.title')}
              </DialogTitle>
              <DialogDescription>
                {t('BackupsPage.importDialog.description')}
              </DialogDescription>
            </DialogHeader>

            {importFile && importPreview && (
              <div className="space-y-4 py-4">
                {/* File Info */}
                <div className="flex items-center gap-3 p-3 bg-muted/50 rounded-lg">
                  <FileJson className="h-8 w-8 text-primary" />
                  <div>
                    <p className="font-medium text-sm">{importFile.name}</p>
                    <p className="text-xs text-muted-foreground">
                      {(importFile.size / 1024).toFixed(2)} KB
                    </p>
                  </div>
                </div>

                {/* What will be imported */}
                <div className="space-y-2">
                  <Label className="text-sm font-medium">{t('BackupsPage.importDialog.contains')}</Label>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="flex justify-between p-2 bg-muted/30 rounded text-sm">
                      <span className="text-muted-foreground">{t('BackupsPage.include.devices')}</span>
                      <span className="font-medium">{importPreviewCount('devices')}</span>
                    </div>
                    <div className="flex justify-between p-2 bg-muted/30 rounded text-sm">
                      <span className="text-muted-foreground">{t('BackupsPage.importDialog.sites')}</span>
                      <span className="font-medium">{importPreviewCount('sites')}</span>
                    </div>
                    <div className="flex justify-between p-2 bg-muted/30 rounded text-sm">
                      <span className="text-muted-foreground">{t('BackupsPage.importDialog.controllers')}</span>
                      <span className="font-medium">{importPreviewCount('controllers')}</span>
                    </div>
                    <div className="flex justify-between p-2 bg-muted/30 rounded text-sm">
                      <span className="text-muted-foreground">{t('BackupsPage.include.users')}</span>
                      <span className="font-medium">{importPreviewCount('users')}</span>
                    </div>
                  </div>
                </div>

                {/* Metadata */}
                {importPreview.metadata && (
                  <div className="p-3 bg-muted/30 rounded-lg text-xs text-muted-foreground space-y-1">
                    <p><span className="font-medium">{t('BackupsPage.importDialog.metadataCreated')}</span> {importPreview.metadata.created_at || t('BackupsPage.importDialog.unknown')}</p>
                    {/* Exports do not carry an author field, collect_backup_data()
                        writes version/schema_version/created_at/freesdn_version only.
                        ``created_by`` would always render "Unknown", so it is omitted. */}
                    <p><span className="font-medium">{t('BackupsPage.importDialog.metadataVersion')}</span> {importPreview.metadata.product_version || t('BackupsPage.importDialog.unknown')}</p>
                  </div>
                )}

                {/* Warning */}
                <div className="flex items-start gap-2 p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                  <AlertTriangle className="h-4 w-4 text-yellow-500 mt-0.5 shrink-0" />
                  <p className="text-sm text-yellow-500">
                    {t('BackupsPage.importDialog.warning')}
                  </p>
                </div>
              </div>
            )}

            <DialogFooter>
              <Button
                variant="outline"
                onClick={() => {
                  setShowImportDialog(false);
                  setImportFile(null);
                  setImportPreview(null);
                }}
              >
                {t('BackupsPage.actions.cancel')}
              </Button>
              <Button
                onClick={handleConfirmImport}
                disabled={isImporting}
                className="gap-2"
              >
                {isImporting ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    {t('BackupsPage.importDialog.importing')}
                  </>
                ) : (
                  <>
                    <Upload className="h-4 w-4" />
                    {t('BackupsPage.importDialog.importNow')}
                  </>
                )}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Bulk Actions */}
        <BulkActionsBar
          selectedCount={selectedBackupIds.size}
          itemName={t('BackupsPage.bulk.itemName')}
          onClear={() => setSelectedBackupIds(new Set())}
          actions={[
            {
              label: t('BackupsPage.actions.restore'),
              icon: RotateCcw,
              onClick: () => {
                const first = backups.find((b: Backup) => selectedBackupIds.has(b.id) && b.status === 'completed');
                if (first) {
                  setRestoreDialogBackup(first);
                  setRestoreOptions(defaultRestoreOptions);
                  setRestoreConfirmText('');
                }
                setSelectedBackupIds(new Set());
              },
            },
            {
              label: t('BackupsPage.actions.download'),
              icon: Download,
              onClick: () => {
                backups.filter((b: Backup) => selectedBackupIds.has(b.id) && b.status === 'completed')
                  .forEach((b: Backup) => downloadBackupMutation.mutate(b));
                setSelectedBackupIds(new Set());
              },
            },
            {
              label: t('BackupsPage.actions.delete'),
              icon: Trash2,
              variant: 'destructive',
              onClick: () => {
                if (confirm(t('BackupsPage.bulk.deleteConfirm', { count: selectedBackupIds.size }))) {
                  selectedBackupIds.forEach((id) => deleteMutation.mutate(id));
                  setSelectedBackupIds(new Set());
                }
              },
            },
          ]}
        />
      </div>
  );
}