// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Plugins Settings Page
 *
 * Manage third-party plugins: install, enable/disable, configure, and uninstall.
 */

import { useState, useRef, useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
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
} from 'lucide-react';

import { api, getApiErrorMessage } from '@/lib/api';
import { useAuthStore } from '@/stores/authStore';
import { EmptyState, ErrorState } from '@/components/ui/empty-state';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
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

  useEffect(() => {
    if (open) {
      setUrlValue('');
      setTab('file');
      setSelectedFile(null);
      setError(null);
      setTrustAcknowledged(false);
    }
  }, [open]);

  const installFileMutation = useMutation({
    mutationFn: (file: File) => {
      const fd = new FormData();
      fd.append('file', file);
      return api.post('/plugins/install', fd);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
      onClose();
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      setError(getApiErrorMessage(err, t('PluginsPage.errors.installFailed')));
    },
  });

  const installUrlMutation = useMutation({
    mutationFn: (url: string) => api.post('/plugins/install-url', { url }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
      onClose();
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      setError(getApiErrorMessage(err, t('PluginsPage.errors.installFailed')));
    },
  });

  const handleInstall = () => {
    setError(null);
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

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>{t('PluginsPage.actions.cancel')}</Button>
          <Button
            onClick={handleInstall}
            disabled={
              isPending ||
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

function PluginCapabilities({ manifest }: { manifest: Record<string, unknown> }) {
  const { t } = useTranslation('settings');
  const permissions = Array.isArray(manifest.permissions) ? manifest.permissions : [];
  const navItems = Array.isArray(manifest.nav_items) ? manifest.nav_items : [];
  const deps = Array.isArray(manifest.dependencies) ? manifest.dependencies : [];
  const hasSettings = !!manifest.settings_schema;
  const hasApi = !!manifest.api_prefix;

  const items: { icon: React.ReactNode; label: string }[] = [];
  if (permissions.length > 0) items.push({ icon: <Shield className="h-3 w-3" />, label: t('PluginsPage.capabilities.permissions', { count: permissions.length }) });
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
}: {
  plugin: Plugin;
  selected: boolean;
  onToggleSelected: () => void;
  onUninstall: () => void;
  // Org-scoped enable/disable (org_admin+ / plugins.admin)
  canToggle: boolean;
  // Platform uninstall (superuser only)
  canUninstall: boolean;
}) {
  const { t } = useTranslation('settings');
  const queryClient = useQueryClient();
  const [expanded, setExpanded] = useState(false);
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
          className="flex flex-1 cursor-pointer items-center gap-4 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset"
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

          {toggleError && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{toggleError}</AlertDescription>
            </Alert>
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
  const [search, setSearch] = useState('');
  const [selectedPluginIds, setSelectedPluginIds] = useState<Set<string>>(new Set());

  const { data: plugins = [], isLoading, isError, refetch } = useQuery<Plugin[]>({
    queryKey: ['plugins'],
    queryFn: () => api.get('/plugins').then((r) => r.data),
  });

  const [uninstallError, setUninstallError] = useState<string | null>(null);

  const uninstallMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/plugins/${id}`),
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
    };
  }, [plugins]);

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
                      selectedPlugins.forEach((p) => uninstallMutation.mutate(p.plugin_id));
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
        onOpenChange={() => setUninstallTarget(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('PluginsPage.uninstallDialog.title')}</AlertDialogTitle>
            <AlertDialogDescription>
              {t('PluginsPage.uninstallDialog.description')}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('PluginsPage.actions.cancel')}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (uninstallTarget) uninstallMutation.mutate(uninstallTarget);
                setUninstallTarget(null);
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
