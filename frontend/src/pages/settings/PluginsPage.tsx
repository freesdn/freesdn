// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Plugins Settings Page
 *
 * Manage third-party plugins: install, enable/disable, configure, and uninstall.
 */

import { useState, useRef, useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Activity,
  Clock,
  Package,
  Upload,
  Trash2,
  ToggleLeft,
  ToggleRight,
  ChevronRight,
  AlertCircle,
  AlertTriangle,
  CheckCircle,
  Loader2,
  ExternalLink,
  Settings,
  X,
  Zap,
  Shield,
  Power,
  PowerOff,
  ArrowUpCircle,
} from 'lucide-react';

import { api, getApiErrorMessage } from '@/lib/api';
import { useAuthStore } from '@/stores/authStore';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Input } from '@/components/ui/input';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { PluginSettingsForm } from './PluginSettingsForm';
import { isUpdateAvailable } from '@/lib/plugin-version';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card } from '@/components/ui/card';
import { PageHeader, PageToolbar } from '@/components/layout';
import { StatsGrid } from '@/components/ui/stats-grid';
import { StatusBadge, type StatusVariant } from '@/components/ui/status-indicator';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { SearchBar } from '@/components/ui/search-bar';
import { cn } from '@/lib/utils';

interface Plugin {
  plugin_id: string;
  name: string;
  version: string;
  description: string | null;
  author: string | null;
  license: string | null;
  homepage: string | null;
  is_active: boolean;
  status: string;
  plugin_dir: string;
  manifest_cache: Record<string, unknown>;
  installed_from: string | null;
}

const PLUGIN_STATUS_VARIANT: Record<string, StatusVariant> = {
  installed: 'success',
  disabled: 'neutral',
  error: 'error',
};

// ─────────────────────────────────────────────────────────────────────────────
// Install dialog
// ─────────────────────────────────────────────────────────────────────────────

function InstallPluginDialog({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const { t } = useTranslation('settings');
  const queryClient = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const [urlValue, setUrlValue] = useState('');
  const [tab, setTab] = useState<'file' | 'url'>('file');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [trustAcknowledged, setTrustAcknowledged] = useState(false);
  // The backend reports when an install landed but the plugin's HTTP endpoints
  // are still serving the previous version. Holding the dialog open is
  // deliberate: closing on success is what made this invisible, and a toast
  // that a busy operator misses leaves them debugging endpoints that quietly
  // disagree with the version number next to them.
  const [restartNote, setRestartNote] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setUrlValue('');
      setTab('file');
      setSelectedFile(null);
      setError(null);
      setTrustAcknowledged(false);
      setRestartNote(null);
    }
  }, [open]);

  const installFileMutation = useMutation({
    mutationFn: (file: File) => {
      const fd = new FormData();
      fd.append('file', file);
      return api.post('/plugins/install', fd);
    },
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
      if (res?.data?.restart_required) {
        setRestartNote(res.data.note ?? t('PluginsPage.install.restartRequired.body'));
        return;
      }
      onClose();
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      setError(getApiErrorMessage(err, t('PluginsPage.errors.installFailed')));
    },
  });

  const installUrlMutation = useMutation({
    mutationFn: (url: string) => api.post('/plugins/install-url', { url }),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
      if (res?.data?.restart_required) {
        setRestartNote(res.data.note ?? t('PluginsPage.install.restartRequired.body'));
        return;
      }
      onClose();
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      setError(getApiErrorMessage(err, t('PluginsPage.errors.installFailed')));
    },
  });

  const handleInstall = () => {
    setError(null);
    setRestartNote(null);
    if (tab === 'file' && selectedFile) {
      installFileMutation.mutate(selectedFile);
    } else if (tab === 'url' && urlValue.trim()) {
      installUrlMutation.mutate(urlValue.trim());
    }
  };

  const isPending = installFileMutation.isPending || installUrlMutation.isPending;

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('PluginsPage.install.title')}</DialogTitle>
          <DialogDescription>
            {t('PluginsPage.install.description')}
          </DialogDescription>
        </DialogHeader>

        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>{t('PluginsPage.install.trustWarningTitle')}</AlertTitle>
          <AlertDescription>
            {t('PluginsPage.install.trustWarningBody')}
          </AlertDescription>
        </Alert>

        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-0.5"
            checked={trustAcknowledged}
            onChange={(e) => setTrustAcknowledged(e.target.checked)}
          />
          <span className="text-muted-foreground">
            {t('PluginsPage.install.trustAcknowledge')}
          </span>
        </label>

        <Tabs value={tab} onValueChange={(v) => setTab(v as 'file' | 'url')}>
          <TabsList className="w-full">
            <TabsTrigger value="file" className="flex-1">{t('PluginsPage.install.uploadZip')}</TabsTrigger>
            <TabsTrigger value="url" className="flex-1">{t('PluginsPage.install.fromUrl')}</TabsTrigger>
          </TabsList>

          <TabsContent value="file" className="mt-4">
            <div
              role="button"
              tabIndex={0}
              aria-label={selectedFile ? t('PluginsPage.install.selectedFileAria', { name: selectedFile.name }) : t('PluginsPage.install.selectFileAria')}
              className={cn(
                'flex cursor-pointer flex-col items-center gap-3 rounded-lg border-2 border-dashed p-8 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                selectedFile
                  ? 'border-success/50 bg-success/10'
                  : 'border-muted-foreground/30 hover:border-primary'
              )}
              onClick={() => fileRef.current?.click()}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileRef.current?.click(); } }}
            >
              {selectedFile ? (
                <>
                  <CheckCircle className="h-8 w-8 text-success" />
                  <p className="text-sm font-medium">{selectedFile.name}</p>
                  <p className="text-xs text-muted-foreground">
                    {(selectedFile.size / 1024).toFixed(1)} KB
                  </p>
                </>
              ) : (
                <>
                  <Upload className="h-8 w-8 text-muted-foreground" />
                  <p className="text-sm text-muted-foreground">
                    {t('PluginsPage.install.selectFilePrompt')}
                  </p>
                </>
              )}
            </div>
            <input
              ref={fileRef}
              type="file"
              accept=".zip"
              className="hidden"
              onChange={(e) => setSelectedFile(e.target.files?.[0] ?? null)}
            />
          </TabsContent>

          <TabsContent value="url" className="mt-4">
            <Input
              placeholder={t('PluginsPage.install.urlPlaceholder')}
              value={urlValue}
              onChange={(e) => setUrlValue(e.target.value)}
            />
          </TabsContent>
        </Tabs>

        {error && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {restartNote && (
          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>{t('PluginsPage.install.restartRequired.title')}</AlertTitle>
            <AlertDescription>{restartNote}</AlertDescription>
          </Alert>
        )}

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {restartNote ? t('PluginsPage.actions.close') : t('PluginsPage.actions.cancel')}
          </Button>
          <Button
            onClick={handleInstall}
            disabled={
              isPending ||
              !!restartNote ||
              !trustAcknowledged ||
              (tab === 'file' && !selectedFile) ||
              (tab === 'url' && !urlValue.trim())
            }
          >
            {isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {t('PluginsPage.actions.install')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Plugin capabilities badges
// ─────────────────────────────────────────────────────────────────────────────

interface OperationHealth {
  calls: number;
  errors: number;
  timeouts: number;
  error_rate: number;
  p95_seconds: number | null;
  last_error: string | null;
}

interface PluginScheduleRun {
  status: string;
  started_at: number;
  duration_ms: number;
  error: string | null;
}

interface PluginScheduleInfo {
  name: string;
  method: string;
  interval_seconds: number;
  description: string;
  enabled: boolean;
  next_run_at: number | null;
  last_run: PluginScheduleRun | null;
  runs_this_worker: number;
  failures_this_worker: number;
}

/** "every 15 min" reads better than 900, and an operator is scanning, not calculating. */
function formatInterval(seconds: number, t: TFunction): string {
  if (seconds % 3600 === 0) return t('PluginsPage.schedules.everyHours', { count: seconds / 3600 });
  if (seconds % 60 === 0) return t('PluginsPage.schedules.everyMinutes', { count: seconds / 60 });
  return t('PluginsPage.schedules.everySeconds', { count: seconds });
}

/** Relative, because "in 4 min" answers the question and a timestamp does not. */
function formatRelative(epochSeconds: number, t: TFunction): string {
  const delta = Math.round(epochSeconds - Date.now() / 1000);
  const abs = Math.abs(delta);
  const value = abs >= 3600 ? Math.round(abs / 3600) : abs >= 60 ? Math.round(abs / 60) : abs;
  const unit = abs >= 3600 ? 'h' : abs >= 60 ? 'm' : 's';
  return delta >= 0
    ? t('PluginsPage.schedules.inFuture', { value, unit })
    : t('PluginsPage.schedules.inPast', { value, unit });
}

/**
 * What this plugin runs unattended, and whether it is actually running.
 *
 * The whole point is `last_run`. A schedule an operator can see declared but
 * cannot see RUNNING is indistinguishable from one that is quietly failing, and
 * unattended work that fails quietly is the failure mode this panel exists for.
 * Until it existed, listing and toggling schedules was possible over the API
 * only -- which for something that runs on somebody's network while they sleep
 * is not a real answer.
 */
function PluginSchedules({ pluginId }: { pluginId: string }) {
  const { t } = useTranslation('settings');
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const { data: schedules = [] } = useQuery<PluginScheduleInfo[]>({
    queryKey: ['plugin-schedules', pluginId],
    queryFn: () => api.get(`/plugins/${pluginId}/schedules`).then((r) => r.data),
    // A run lands within 15s of its slot, so anything slower shows an operator
    // a "next run" that has already been and gone.
    refetchInterval: 15_000,
  });

  const toggle = useMutation({
    mutationFn: ({ name, enabled }: { name: string; enabled: boolean }) =>
      api.put(`/plugins/${pluginId}/schedules/${name}`, { enabled }),
    onSuccess: () => {
      setError(null);
      queryClient.invalidateQueries({ queryKey: ['plugin-schedules', pluginId] });
    },
    onError: (e) => setError(getApiErrorMessage(e)),
  });

  if (schedules.length === 0) return null;

  return (
    <div className="space-y-2 rounded-md border border-border p-3">
      <div className="flex items-center gap-2">
        <Clock className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="text-xs font-medium">{t('PluginsPage.schedules.title')}</span>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <div className="space-y-2">
        {schedules.map((s) => {
          const failed = s.last_run !== null && s.last_run.status !== 'ok';
          return (
            <div key={s.name} className="space-y-1 rounded border border-border/60 p-2">
              <div className="flex flex-wrap items-center gap-2">
                <code className="text-[11px] font-medium">{s.name}</code>
                <span className="text-xs text-muted-foreground">
                  {formatInterval(s.interval_seconds, t)}
                </span>
                {s.last_run !== null && (
                  <StatusBadge variant={failed ? 'error' : 'success'}>
                    {s.last_run.status}
                  </StatusBadge>
                )}
                <Switch
                  className="ml-auto"
                  checked={s.enabled}
                  disabled={toggle.isPending}
                  onCheckedChange={(enabled) => toggle.mutate({ name: s.name, enabled })}
                  aria-label={t('PluginsPage.schedules.toggleAria', { name: s.name })}
                />
              </div>

              {s.description && (
                <p className="text-xs text-muted-foreground">{s.description}</p>
              )}

              <div className="flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-muted-foreground tabular-nums">
                {s.enabled && s.next_run_at !== null && (
                  <span>
                    {t('PluginsPage.schedules.nextRun')} {formatRelative(s.next_run_at, t)}
                  </span>
                )}
                {/* Never run AND enabled is the state worth calling out: it is
                    what a broken schedule looks like from outside. */}
                {s.enabled && s.last_run === null && (
                  <span>{t('PluginsPage.schedules.neverRun')}</span>
                )}
                {s.last_run !== null && (
                  <span>
                    {t('PluginsPage.schedules.lastRun')} {formatRelative(s.last_run.started_at, t)}
                    {' · '}
                    {Math.round(s.last_run.duration_ms)}ms
                  </span>
                )}
                {/* Named honestly: the counters are per API worker, and under
                    several workers the real totals are higher. last_run is not
                    affected -- it is shared through Redis. */}
                {s.runs_this_worker > 0 && (
                  <span>
                    {t('PluginsPage.schedules.runsThisWorker', {
                      runs: s.runs_this_worker,
                      failures: s.failures_this_worker,
                    })}
                  </span>
                )}
              </div>

              {failed && s.last_run?.error && (
                <p className="text-xs text-destructive">{s.last_run.error}</p>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

interface PluginSupervisionState {
  plugin_id: string;
  state: 'healthy' | 'degraded' | 'quarantined';
  quarantined_for_seconds: number;
  quarantine_reason: string | null;
  quarantine_count: number;
  operations: Record<string, OperationHealth>;
  totals: { calls: number; errors: number };
}

/**
 * What supervision knows about a plugin, which is the part a plugin cannot
 * self-report.
 *
 * A plugin quarantined for failing every event will happily answer "status: ok"
 * to its own health check. Its error rate, its latency and whether the platform
 * has stopped calling it are observations from outside, and until this panel
 * existed they were only visible by scraping Prometheus or reading logs that
 * did not name the plugin.
 */
function PluginSupervision({ pluginId }: { pluginId: string }) {
  const { t } = useTranslation('settings');
  const queryClient = useQueryClient();

  const { data } = useQuery<{ quarantined: string[]; plugins: Record<string, PluginSupervisionState> }>({
    queryKey: ['plugin-supervision'],
    queryFn: () => api.get('/plugins/supervision').then((r) => r.data),
    // Health goes stale quickly and this panel is only open while someone is
    // looking at it, which is exactly when it should be current.
    refetchInterval: 15_000,
  });

  const resetMutation = useMutation({
    mutationFn: () => api.post(`/plugins/${pluginId}/supervision/reset`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['plugin-supervision'] }),
  });

  const health = data?.plugins?.[pluginId];
  // No record means the plugin has not been called yet. That is not a problem,
  // and rendering "healthy" for it would imply an observation nobody made.
  if (!health || health.totals.calls === 0) return null;

  const quarantined = health.state === 'quarantined';
  const degraded = health.state === 'degraded';

  return (
    <div className="space-y-2 rounded-md border border-border p-3">
      <div className="flex items-center gap-2">
        <Activity
          className={
            quarantined
              ? 'h-3.5 w-3.5 text-destructive'
              : degraded
                ? 'h-3.5 w-3.5 text-warning'
                : 'h-3.5 w-3.5 text-muted-foreground'
          }
        />
        <span className="text-xs font-medium">{t('PluginsPage.supervision.title')}</span>
        <StatusBadge variant={quarantined ? 'error' : degraded ? 'severity_medium' : 'success'}>
          {health.state}
        </StatusBadge>
        {quarantined && (
          <Button
            size="sm"
            variant="outline"
            className="ml-auto"
            onClick={() => resetMutation.mutate()}
            disabled={resetMutation.isPending}
          >
            {t('PluginsPage.supervision.reset')}
          </Button>
        )}
      </div>

      {quarantined && health.quarantine_reason && (
        <p className="text-xs text-destructive">
          {health.quarantine_reason} ({Math.ceil(health.quarantined_for_seconds)}s)
        </p>
      )}

      <div className="grid gap-1 text-xs text-muted-foreground sm:grid-cols-2">
        {Object.entries(health.operations)
          .filter(([, op]) => op.calls > 0)
          .map(([name, op]) => (
            <div key={name} className="flex items-center gap-2">
              <code className="text-[11px]">{name}</code>
              <span className="tabular-nums">
                {op.calls} calls
                {op.errors > 0 && (
                  <span className="text-destructive">
                    {' '}
                    · {op.errors} err ({Math.round(op.error_rate * 100)}%)
                  </span>
                )}
                {op.p95_seconds !== null && <> · p95 {(op.p95_seconds * 1000).toFixed(0)}ms</>}
              </span>
            </div>
          ))}
      </div>
    </div>
  );
}

interface CapabilityInfo {
  code: string;
  summary: string;
  core_permissions: string[];
  mutating: boolean;
}

/**
 * What a plugin is actually allowed to do, in FreeSDN's own words.
 *
 * The manifest carries a `name` and `description` per permission, but both are
 * written by the PLUGIN AUTHOR. A plugin can label `devices.stage` as "Read
 * Alerts", and an operator approving the install would be reading the author's
 * wording rather than what the code grants. So the summary is looked up from
 * /plugins/capabilities by code, and the author's text is not shown here at all.
 *
 * Mutating capabilities are listed first and marked, because "may propose a
 * device configuration change" is a materially different decision from "may
 * read the inventory", and a flat list of equal-weight badges hid that.
 */
function PluginPermissionList({ manifest }: { manifest: Record<string, unknown> }) {
  const { t } = useTranslation('settings');
  const { data: catalogue = [] } = useQuery<CapabilityInfo[]>({
    queryKey: ['plugin-capabilities'],
    queryFn: () => api.get('/plugins/capabilities').then((r) => r.data),
    staleTime: Infinity, // a fixed vocabulary; it changes only on upgrade
  });

  const declared = Array.isArray(manifest.permissions) ? manifest.permissions : [];
  const codes = declared
    .map((p) => (p && typeof p === 'object' ? String((p as { code?: unknown }).code ?? '') : ''))
    .filter(Boolean);
  if (codes.length === 0) return null;

  const byCode = new Map(catalogue.map((c) => [c.code, c]));
  const rows = codes
    .map((code) => byCode.get(code) ?? { code, summary: '', core_permissions: [], mutating: false })
    .sort((a, b) => Number(b.mutating) - Number(a.mutating) || a.code.localeCompare(b.code));

  return (
    <div className="space-y-1.5">
      <div className="text-xs font-medium text-muted-foreground">
        {t('PluginsPage.capabilities.permissions', { count: rows.length })}
      </div>
      <ul className="space-y-1">
        {rows.map((c) => (
          <li key={c.code} className="flex items-start gap-2 text-sm">
            <Shield
              className={
                c.mutating ? 'mt-0.5 h-3.5 w-3.5 shrink-0 text-warning' : 'mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground'
              }
            />
            <span>
              <code className="text-xs">{c.code}</code>
              {c.summary && <span className="text-muted-foreground"> {c.summary}</span>}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function PluginCapabilities({ manifest }: { manifest: Record<string, unknown> }) {
  const { t } = useTranslation('settings');
  const navItems = Array.isArray(manifest.nav_items) ? manifest.nav_items : [];
  const deps = Array.isArray(manifest.dependencies) ? manifest.dependencies : [];
  const hasSettings = !!manifest.settings_schema;
  const hasApi = !!manifest.api_prefix;

  const items: { icon: React.ReactNode; label: string }[] = [];
  // No permission-count badge here: PluginPermissionList renders the codes and
  // the platform's summary for each. "3 permissions" told an operator nothing
  // about whether one of them could propose a device write.
  if (navItems.length > 0) items.push({ icon: <Settings className="h-3 w-3" />, label: t('PluginsPage.capabilities.uiPages') });
  if (hasApi) items.push({ icon: <Zap className="h-3 w-3" />, label: t('PluginsPage.capabilities.restApi') });
  if (hasSettings) items.push({ icon: <Settings className="h-3 w-3" />, label: t('PluginsPage.capabilities.configurable') });
  if (deps.length > 0) items.push({ icon: <Package className="h-3 w-3" />, label: t('PluginsPage.capabilities.dependencies', { count: deps.length }) });

  if (items.length === 0) return null;

  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((b, i) => (
        <Badge key={i} variant="outline" className="gap-1">
          {b.icon}
          {b.label}
        </Badge>
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Plugin row
// ─────────────────────────────────────────────────────────────────────────────

function PluginRow({
  plugin,
  selected,
  onToggleSelected,
  onUninstall,
  canToggle,
  canUninstall,
  update,
}: {
  plugin: Plugin;
  selected: boolean;
  onToggleSelected: () => void;
  onUninstall: () => void;
  // Org-scoped enable/disable (org_admin+ / plugins.admin)
  canToggle: boolean;
  // Platform uninstall (superuser only)
  canUninstall: boolean;
  // The catalogue's newer version, when there is one. Null is the normal case.
  update: { slug: string; version: string } | null;
}) {
  const { t } = useTranslation('settings');
  const queryClient = useQueryClient();
  const [expanded, setExpanded] = useState(false);
  const [updateError, setUpdateError] = useState<string | null>(null);

  const upgradeMutation = useMutation({
    mutationFn: () => api.post(`/marketplace/plugins/${update?.slug}/upgrade`),
    onSuccess: () => {
      setUpdateError(null);
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
      queryClient.invalidateQueries({ queryKey: ['marketplace-plugins'] });
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => setUpdateError(getApiErrorMessage(err, t('PluginsPage.errors.updateFailed'))),
  });
  const [toggleError, setToggleError] = useState<string | null>(null);

  const toggleMutation = useMutation({
    mutationFn: (enable: boolean) =>
      api.post(`/plugins/${plugin.plugin_id}/${enable ? 'enable' : 'disable'}`),
    onSuccess: () => {
      setToggleError(null);
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      setToggleError(getApiErrorMessage(err, t('PluginsPage.errors.toggleFailed')));
    },
  });

  return (
    <Card>
      <div className="flex items-center gap-3 px-4 py-3">
        {(canToggle || canUninstall) && (
          <input
            type="checkbox"
            checked={selected}
            onChange={onToggleSelected}
            onClick={(e) => e.stopPropagation()}
            aria-label={t('PluginsPage.row.selectAria', { name: plugin.name })}
            className="h-4 w-4"
          />
        )}
        <div
          role="button"
          tabIndex={0}
          aria-expanded={expanded}
          aria-label={`${plugin.name} · ${plugin.status}`}
          // min-w-0 is load-bearing: without it this flex child refuses to shrink
          // below its content's min-content width, so the `truncate` on the
          // description inside could never take effect and a long description ran
          // straight off the right edge of the card.
          className="flex min-w-0 flex-1 cursor-pointer items-center gap-4 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset"
          onClick={() => setExpanded(!expanded)}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setExpanded(!expanded); } }}
        >
          <div className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-md bg-muted">
            <Package className="h-5 w-5 text-muted-foreground" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-medium">{plugin.name}</span>
              <Badge variant="outline" className="text-xs">{plugin.version}</Badge>
              <StatusBadge variant={PLUGIN_STATUS_VARIANT[plugin.status] || 'neutral'}>
                {t(`PluginsPage.status.${plugin.status}`, { defaultValue: plugin.status })}
              </StatusBadge>
              {update && (
                <Badge variant="outline" className="gap-1 border-warning text-warning text-xs">
                  <ArrowUpCircle className="h-3 w-3" />
                  {t('PluginsPage.row.updateAvailable', { version: update.version })}
                </Badge>
              )}
            </div>
            {plugin.description && (
              <p className="mt-0.5 truncate text-sm text-muted-foreground">{plugin.description}</p>
            )}
          </div>
          <ChevronRight
            className={cn(
              'h-4 w-4 flex-shrink-0 text-muted-foreground transition-transform',
              expanded && 'rotate-90'
            )}
          />
        </div>
      </div>

      {expanded && (
        <div className="border-t px-4 py-3 space-y-3">
          {plugin.author && (
            <p className="text-sm text-muted-foreground">
              {t('PluginsPage.row.by')} <span className="text-foreground">{plugin.author}</span>
              {plugin.license && <span> · {plugin.license}</span>}
            </p>
          )}
          {plugin.homepage && /^https?:\/\//i.test(plugin.homepage) && (
            <a
              href={plugin.homepage}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-sm text-primary hover:underline"
              onClick={(e) => e.stopPropagation()}
            >
              <ExternalLink className="h-3.5 w-3.5" />
              {t('PluginsPage.row.homepage')}
            </a>
          )}

          <PluginCapabilities manifest={plugin.manifest_cache} />
          <PluginPermissionList manifest={plugin.manifest_cache} />
          <PluginSettingsForm
            pluginId={plugin.plugin_id}
            manifest={plugin.manifest_cache}
          />
          <PluginSchedules pluginId={plugin.plugin_id} />
          <PluginSupervision pluginId={plugin.plugin_id} />

          {toggleError && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{toggleError}</AlertDescription>
            </Alert>
          )}

          {updateError && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{updateError}</AlertDescription>
            </Alert>
          )}

          {update && canUninstall && (
            <Button
              size="sm"
              onClick={(e) => {
                e.stopPropagation();
                upgradeMutation.mutate();
              }}
              disabled={upgradeMutation.isPending}
            >
              {upgradeMutation.isPending ? (
                <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />
              ) : (
                <ArrowUpCircle className="mr-2 h-3.5 w-3.5" />
              )}
              {t('PluginsPage.row.updateTo', { from: plugin.version, to: update.version })}
            </Button>
          )}

          {(canToggle || canUninstall) && (
            <div className="flex items-center gap-2">
              {canToggle && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={(e) => {
                    e.stopPropagation();
                    toggleMutation.mutate(!plugin.is_active);
                  }}
                  disabled={toggleMutation.isPending}
                >
                  {plugin.is_active ? (
                    <>
                      <ToggleRight className="mr-2 h-3.5 w-3.5 text-success" />
                      {t('PluginsPage.actions.disable')}
                    </>
                  ) : (
                    <>
                      <ToggleLeft className="mr-2 h-3.5 w-3.5" />
                      {t('PluginsPage.actions.enable')}
                    </>
                  )}
                </Button>
              )}
              {canUninstall && (
                <Button
                  size="sm"
                  variant="outline"
                  className="text-destructive hover:bg-destructive/10"
                  onClick={(e) => {
                    e.stopPropagation();
                    onUninstall();
                  }}
                >
                  <Trash2 className="mr-2 h-3.5 w-3.5" />
                  {t('PluginsPage.actions.uninstall')}
                </Button>
              )}
            </div>
          )}
        </div>
      )}
    </Card>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Page
// ─────────────────────────────────────────────────────────────────────────────

export default function PluginsPage() {
  const { t } = useTranslation('settings');
  const queryClient = useQueryClient();
  const { hasPermission } = useAuthStore();
  const user = useAuthStore((s) => s.user);
  // Platform-management actions (install / install-from-URL / uninstall /
  // bulk-uninstall) are hard-gated on is_superuser by the backend
  // (_require_plugin_platform_admin in plugins.py). Showing them to
  // settings:* admins just produces guaranteed 403s.
  const canPlatformManagePlugins = !!user?.is_superuser;
  // Org-scoped enable/disable (the per-plugin toggle + bulk enable/disable) is
  // permitted by the backend for org admins (_require_org_admin in plugins.py
  // → is_org_admin OR plugins.admin permission), not just superusers.
  const canToggleOrgPlugins = !!user?.is_org_admin || hasPermission('plugins.admin');
  const [installOpen, setInstallOpen] = useState(false);
  const [uninstallTarget, setUninstallTarget] = useState<string | null>(null);
  // Settings survive an uninstall by default, which is what makes
  // uninstall-reinstall a safe troubleshooting step. The cost is that a stored
  // credential outlives the plugin that used it, so removing one you are
  // actually done with needs a way to take the token with it.
  const [purgeSettings, setPurgeSettings] = useState(false);
  const [search, setSearch] = useState('');
  const [selectedPluginIds, setSelectedPluginIds] = useState<Set<string>>(new Set());

  const { data: plugins = [], isLoading, isError, refetch } = useQuery<Plugin[]>({
    queryKey: ['plugins'],
    queryFn: () => api.get('/plugins').then((r) => r.data),
  });

  // The catalogue, so this page can answer "which of these are out of date".
  // It could not before: the marketplace knew, and the page an operator
  // actually manages plugins from did not, so staying current meant browsing
  // the marketplace and comparing version numbers by eye.
  const { data: catalogue } = useQuery<{ plugins: { plugin_id: string; slug: string; latest_version: string }[] }>({
    queryKey: ['marketplace-plugins', 'for-updates'],
    queryFn: () => api.get('/marketplace/plugins/?page_size=200').then((r) => r.data),
    staleTime: 60_000,
  });

  const available = useMemo(() => {
    const m = new Map<string, { slug: string; version: string }>();
    for (const c of catalogue?.plugins ?? []) {
      m.set(c.plugin_id, { slug: c.slug, version: c.latest_version });
    }
    return m;
  }, [catalogue]);

  const updatesFor = (p: Plugin) => {
    const entry = available.get(p.plugin_id);
    if (!entry || !isUpdateAvailable(p.version, entry.version)) return null;
    return entry;
  };

  const [uninstallError, setUninstallError] = useState<string | null>(null);

  const uninstallMutation = useMutation({
    mutationFn: ({ id, purge }: { id: string; purge: boolean }) =>
      api.delete(`/plugins/${id}`, { params: purge ? { purge_settings: true } : undefined }),
    onSuccess: () => {
      setUninstallError(null);
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      setUninstallError(getApiErrorMessage(err, t('PluginsPage.errors.uninstallFailed')));
    },
  });

  const toggleMutation = useMutation({
    mutationFn: ({ id, enable }: { id: string; enable: boolean }) =>
      api.post(`/plugins/${id}/${enable ? 'enable' : 'disable'}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['plugins'] }),
  });

  const filteredPlugins = useMemo(() => {
    if (!search) return plugins;
    const q = search.toLowerCase();
    return plugins.filter(
      (p) => p.name.toLowerCase().includes(q) || (p.description || '').toLowerCase().includes(q),
    );
  }, [plugins, search]);

  const stats = useMemo(() => {
    return {
      total: plugins.length,
      enabled: plugins.filter((p) => p.is_active).length,
      disabled: plugins.filter((p) => !p.is_active).length,
      error: plugins.filter((p) => p.status === 'error').length,
      updatable: plugins.filter((p) => {
        const entry = available.get(p.plugin_id);
        return entry ? isUpdateAvailable(p.version, entry.version) : false;
      }).length,
    };
  }, [plugins, available]);

  const selectedPlugins = useMemo(
    () => plugins.filter((p) => selectedPluginIds.has(p.plugin_id)),
    [plugins, selectedPluginIds],
  );

  const toggleSelected = (id: string) => {
    setSelectedPluginIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  if (isError) {
    return (
      <div className="space-y-6">
        <PageHeader
          icon={Package}
          title={t('PluginsPage.header.title')}
          description={t('PluginsPage.header.description')}
        />
        <ErrorState message={t('PluginsPage.errors.loadFailed')} onRetry={() => refetch()} />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Package}
        title={t('PluginsPage.header.title')}
        description={t('PluginsPage.header.description')}
        onRefresh={() => refetch()}
        refreshing={isLoading}
        primaryAction={
          canPlatformManagePlugins
            ? { label: t('PluginsPage.actions.installPlugin'), icon: Upload, onClick: () => setInstallOpen(true) }
            : undefined
        }
      />

      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          { title: t('PluginsPage.stats.total.title'), value: stats.total, icon: Package, variant: 'default', description: t('PluginsPage.stats.total.description') },
          { title: t('PluginsPage.stats.enabled.title'), value: stats.enabled, icon: Power, variant: 'success', description: t('PluginsPage.stats.enabled.description') },
          { title: t('PluginsPage.stats.disabled.title'), value: stats.disabled, icon: PowerOff, variant: 'default', description: t('PluginsPage.stats.disabled.description') },
          { title: t('PluginsPage.stats.errors.title'), value: stats.error, icon: AlertCircle, variant: 'destructive', description: t('PluginsPage.stats.errors.description') },
          { title: t('PluginsPage.stats.updates.title'), value: stats.updatable, icon: ArrowUpCircle, variant: stats.updatable > 0 ? 'warning' : 'default', description: t('PluginsPage.stats.updates.description') },
        ]}
      />

      <PageToolbar>
        <SearchBar
          value={search}
          onChange={setSearch}
          placeholder={t('PluginsPage.searchPlaceholder')}
          className="w-full sm:w-auto"
        />
        {search && (
          <Button variant="ghost" size="sm" onClick={() => setSearch('')}>
            {t('PluginsPage.actions.clearFilters')}
          </Button>
        )}
      </PageToolbar>

      {!isLoading && filteredPlugins.length === 0 && (
        <EmptyState
          icon={Package}
          title={t('PluginsPage.empty.title')}
          description={t('PluginsPage.empty.description')}
          action={canPlatformManagePlugins ? { label: t('PluginsPage.actions.installPlugin'), onClick: () => setInstallOpen(true), icon: Upload } : undefined}
          variant="card"
        />
      )}

      <div className="space-y-3">
        {filteredPlugins.map((plugin) => (
          <PluginRow
            key={plugin.plugin_id}
            plugin={plugin}
            selected={selectedPluginIds.has(plugin.plugin_id)}
            onToggleSelected={() => toggleSelected(plugin.plugin_id)}
            onUninstall={() => setUninstallTarget(plugin.plugin_id)}
            canToggle={canToggleOrgPlugins}
            update={updatesFor(plugin)}
            canUninstall={canPlatformManagePlugins}
          />
        ))}
      </div>

      <BulkActionsBar
        selectedCount={selectedPlugins.length}
        itemName={t('PluginsPage.itemName')}
        onClear={() => setSelectedPluginIds(new Set())}
        actions={[
          // Org-scoped enable/disable, org_admin+ / plugins.admin (matches
          // _require_org_admin on the enable/disable endpoints).
          ...(canToggleOrgPlugins
            ? [
                {
                  label: t('PluginsPage.actions.enable'),
                  icon: Power,
                  onClick: () => {
                    selectedPlugins.forEach((p) => {
                      if (!p.is_active) toggleMutation.mutate({ id: p.plugin_id, enable: true });
                    });
                    setSelectedPluginIds(new Set());
                  },
                },
                {
                  label: t('PluginsPage.actions.disable'),
                  icon: PowerOff,
                  onClick: () => {
                    selectedPlugins.forEach((p) => {
                      if (p.is_active) toggleMutation.mutate({ id: p.plugin_id, enable: false });
                    });
                    setSelectedPluginIds(new Set());
                  },
                },
              ]
            : []),
          // Bulk uninstall is platform management, superuser only (matches
          // _require_plugin_platform_admin on DELETE /plugins/{id}).
          ...(canPlatformManagePlugins
            ? [
                {
                  label: t('PluginsPage.actions.uninstall'),
                  icon: Trash2,
                  variant: 'destructive' as const,
                  onClick: () => {
                    if (confirm(t('PluginsPage.confirmBulkUninstall', { count: selectedPlugins.length }))) {
                      selectedPlugins.forEach((p) =>
                        uninstallMutation.mutate({ id: p.plugin_id, purge: false }),
                      );
                      setSelectedPluginIds(new Set());
                    }
                  },
                },
              ]
            : []),
        ]}
      />

      {uninstallError && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription className="flex items-center justify-between">
            {uninstallError}
            <Button variant="ghost" size="sm" onClick={() => setUninstallError(null)}>
              <X className="h-3.5 w-3.5" />
            </Button>
          </AlertDescription>
        </Alert>
      )}

      <InstallPluginDialog
        open={installOpen}
        onClose={() => setInstallOpen(false)}
      />

      <AlertDialog
        open={!!uninstallTarget}
        onOpenChange={() => {
          setUninstallTarget(null);
          setPurgeSettings(false);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('PluginsPage.uninstallDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('PluginsPage.uninstallDialog.description')}
            </AlertDialogDescription>
          </AlertDialogHeader>

          <label className="flex items-start gap-2 rounded-md border border-border p-3 text-sm">
            <input
              type="checkbox"
              checked={purgeSettings}
              onChange={(e) => setPurgeSettings(e.target.checked)}
              className="mt-0.5 h-4 w-4"
            />
            <span>
              <span className="font-medium">
                {t('PluginsPage.uninstallDialog.purgeLabel')}
              </span>
              <span className="block text-xs text-muted-foreground">
                {t('PluginsPage.uninstallDialog.purgeHint')}
              </span>
            </span>
          </label>

          <AlertDialogFooter>
            <AlertDialogCancel>{t('PluginsPage.actions.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (uninstallTarget) {
                  uninstallMutation.mutate({ id: uninstallTarget, purge: purgeSettings });
                }
                setUninstallTarget(null);
                setPurgeSettings(false);
              }}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {t('PluginsPage.actions.uninstall')}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
