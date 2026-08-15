// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Webhooks Management Page
 *
 * Canonical list-page pattern.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import React, { useState, useEffect, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';
import { PageHeader, PageToolbar } from '@/components/layout';
import { webhooksApi, Webhook, WebhookDelivery, getApiErrorMessage } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Checkbox } from '@/components/ui/checkbox';
import { Skeleton } from '@/components/ui/skeleton';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { SearchBar } from '@/components/ui/search-bar';
import { StatsGrid } from '@/components/ui/stats-grid';
import { StatusBadge, type StatusVariant } from '@/components/ui/status-indicator';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { ErrorState } from '@/components/ui/empty-state';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { FormDialog } from '@/components/ui/form-dialog';
import {
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Webhook as WebhookIcon,
  Plus,
  MoreHorizontal,
  FlaskConical,
  ClipboardList,
  Trash2,
  CheckCircle,
  XCircle,
  Power,
  Download,
} from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';

const DELIVERY_STATUS_VARIANT: Record<string, StatusVariant> = {
  delivered: 'success',
  failed: 'error',
  pending: 'pending',
  retrying: 'updating',
};

interface CreateWebhookModalProps {
  isOpen: boolean;
  onClose: () => void;
  onCreate: (data: Partial<Webhook>) => Promise<unknown> | unknown;
}

const buildWebhookSchema = (t: TFunction) =>
  z.object({
    name: z.string().trim().min(1, t('WebhooksPage.validation.nameRequired')),
    url: z
      .string()
      .trim()
      .min(1, t('WebhooksPage.validation.urlRequired'))
      .url(t('WebhooksPage.validation.urlInvalid')),
    secret: z.string(),
    event_types: z.array(z.string()),
    enabled: z.boolean(),
    verify_ssl: z.boolean(),
  });
type WebhookFormValues = z.infer<ReturnType<typeof buildWebhookSchema>>;

const CreateWebhookModal: React.FC<CreateWebhookModalProps> = ({ isOpen, onClose, onCreate }) => {
  const { t } = useTranslation('webhooks');
  const [eventInput, setEventInput] = useState('');
  const webhookSchema = buildWebhookSchema(t);

  return (
    <FormDialog<WebhookFormValues>
      open={isOpen}
      onOpenChange={(next) => {
        if (!next) {
          setEventInput('');
          onClose();
        }
      }}
      title={t('WebhooksPage.create.title')}
      schema={webhookSchema}
      defaultValues={{
        name: '',
        url: '',
        secret: '',
        event_types: [],
        enabled: true,
        verify_ssl: true,
      }}
      submitLabel={t('WebhooksPage.create.submit')}
      contentClassName="max-w-lg"
      onSubmit={async (values) => {
        await onCreate(values);
      }}
    >
      {(form) => {
        const eventTypes = form.watch('event_types');
        const addEventType = () => {
          const trimmed = eventInput.trim();
          if (trimmed && !eventTypes.includes(trimmed)) {
            form.setValue('event_types', [...eventTypes, trimmed]);
            setEventInput('');
          }
        };
        const removeEventType = (type: string) => {
          form.setValue('event_types', eventTypes.filter((t) => t !== type));
        };

        return (
          <>
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('WebhooksPage.fields.name.label')}</FormLabel>
                  <FormControl>
                    <Input placeholder={t('WebhooksPage.fields.name.placeholder')} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="url"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('WebhooksPage.fields.url.label')}</FormLabel>
                  <FormControl>
                    <Input
                      type="url"
                      placeholder="https://example.com/webhook"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="secret"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('WebhooksPage.fields.secret.label')}</FormLabel>
                  <FormControl>
                    <Input
                      type="password"
                      placeholder={t('WebhooksPage.fields.secret.placeholder')}
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormItem>
              <FormLabel>{t('WebhooksPage.fields.eventTypes.label')}</FormLabel>
              <div className="flex space-x-2">
                <Input
                  value={eventInput}
                  onChange={(e) => setEventInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      addEventType();
                    }
                  }}
                  placeholder="device.online"
                  className="flex-1"
                />
                <Button type="button" variant="secondary" onClick={addEventType}>
                  {t('WebhooksPage.fields.eventTypes.add')}
                </Button>
              </div>
              {eventTypes.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-2">
                  {eventTypes.map((type) => (
                    <span
                      key={type}
                      className="px-2 py-1 text-xs font-medium rounded bg-primary/10 text-primary flex items-center space-x-1"
                    >
                      <span>{type}</span>
                      <button
                        type="button"
                        onClick={() => removeEventType(type)}
                        className="text-primary hover:text-primary/80 ml-1"
                      >
                        x
                      </button>
                    </span>
                  ))}
                </div>
              )}
              <FormDescription>{t('WebhooksPage.fields.eventTypes.description')}</FormDescription>
            </FormItem>
            <div className="flex items-center space-x-6">
              <FormField
                control={form.control}
                name="enabled"
                render={({ field }) => (
                  <div className="flex items-center space-x-2">
                    <Checkbox
                      id="webhook-enabled"
                      checked={field.value}
                      onCheckedChange={(checked) => field.onChange(!!checked)}
                    />
                    <Label htmlFor="webhook-enabled">{t('WebhooksPage.fields.enabled')}</Label>
                  </div>
                )}
              />
              <FormField
                control={form.control}
                name="verify_ssl"
                render={({ field }) => (
                  <div className="flex items-center space-x-2">
                    <Checkbox
                      id="webhook-ssl"
                      checked={field.value}
                      onCheckedChange={(checked) => field.onChange(!!checked)}
                    />
                    <Label htmlFor="webhook-ssl">{t('WebhooksPage.fields.verifySsl')}</Label>
                  </div>
                )}
              />
            </div>
          </>
        );
      }}
    </FormDialog>
  );
};

interface DeliveriesModalProps {
  webhookId: string | null;
  onClose: () => void;
}

const DeliveriesModal: React.FC<DeliveriesModalProps> = ({ webhookId, onClose }) => {
  const { t } = useTranslation('webhooks');
  const [deliveries, setDeliveries] = useState<WebhookDelivery[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const loadDeliveries = useCallback(async () => {
    if (!webhookId) return;
    try {
      setLoading(true);
      setLoadError(null);
      const response = await webhooksApi.getDeliveries(webhookId, { per_page: 20 });
      // Backend returns ``{items, total, page, per_page}``, not a
      // bare array. Previously ``setDeliveries(response.data || [])``
      // stored the wrapper object, and the next ``deliveries.map``
      // crashed with "deliveries.map is not a function" as soon as
      // a webhook had any delivery rows.
      setDeliveries(response.data?.items || []);
    } catch (err) {
      // Surface the load failure as a distinct error state instead of
      // masking it as an empty "no deliveries yet" list.
      setLoadError(getApiErrorMessage(err, t('WebhooksPage.errorState.message')));
    } finally {
      setLoading(false);
    }
  }, [webhookId, t]);

  useEffect(() => {
    if (!webhookId) return;
    loadDeliveries();
  }, [webhookId, loadDeliveries]);

  return (
    <Dialog open={!!webhookId} onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent className="max-w-3xl max-h-[80vh] overflow-auto">
        <DialogHeader>
          <DialogTitle>{t('WebhooksPage.deliveries.title')}</DialogTitle>
        </DialogHeader>

        <div>
          {loading ? (
            <div className="space-y-3 py-4">
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-16 w-full" />
              <Skeleton className="h-16 w-full" />
            </div>
          ) : loadError ? (
            <ErrorState message={loadError} onRetry={() => loadDeliveries()} />
          ) : deliveries.length === 0 ? (
            <p className="text-center text-muted-foreground py-8">{t('WebhooksPage.deliveries.empty')}</p>
          ) : (
            <div className="space-y-3">
              {deliveries.map((delivery) => (
                <div key={delivery.id} className="p-4 bg-muted rounded-lg">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <StatusBadge variant={DELIVERY_STATUS_VARIANT[delivery.status] ?? 'unknown'}>
                        {delivery.status}
                      </StatusBadge>
                      <span className="text-sm text-muted-foreground">
                        {t('WebhooksPage.deliveries.attempt', { n: delivery.attempt_number })}
                      </span>
                    </div>
                    <span className="text-sm text-muted-foreground">
                      {new Date(delivery.created_at).toLocaleString()}
                    </span>
                  </div>
                  {delivery.response_code && (
                    <p className="text-sm text-muted-foreground mt-2">
                      {t('WebhooksPage.deliveries.response', { code: delivery.response_code })}
                    </p>
                  )}
                  {delivery.error_message && (
                    <p className="text-sm text-destructive mt-2">{delivery.error_message}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
};

export default function WebhooksPage() {
  const { t } = useTranslation('webhooks');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [viewDeliveriesId, setViewDeliveriesId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selectedWebhooks, setSelectedWebhooks] = useState<Webhook[]>([]);

  // Query webhooks. Request the backend's max page size (per_page caps at
  // 100, see backend/app/api/v1/endpoints/webhooks.py) so search/filter/stats
  // operate over the full set instead of silently truncating at the default
  // 20-row first page.
  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ['webhooks'],
    queryFn: async () => {
      const response = await webhooksApi.list({ per_page: 100 });
      return response.data;
    },
  });

  const allWebhooks: Webhook[] = data?.items || [];
  // Server-reported total (may exceed the 100 rows we fetched). Used for the
  // headline "total" stat so the count stays honest beyond one page.
  const serverTotal = data?.total ?? allWebhooks.length;

  // Mutations
  const createMutation = useMutation({
    mutationFn: (data: Partial<Webhook>) => webhooksApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] });
      setShowCreateModal(false);
    },
    onError: (err: any) => {
      toast({ title: t('WebhooksPage.toast.error'), description: t('WebhooksPage.toast.createFailed', { detail: getApiErrorMessage(err, err.message) }), variant: 'destructive' });
    },
  });

  const toggleMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) => {
      if (enabled) return webhooksApi.enable(id);
      return webhooksApi.disable(id);
    },
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['webhooks'] }),
    onError: (err: any) => {
      toast({ title: t('WebhooksPage.toast.error'), description: t('WebhooksPage.toast.updateFailed', { detail: getApiErrorMessage(err, err.message) }), variant: 'destructive' });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => webhooksApi.delete(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['webhooks'] }),
    onError: (err: any) => {
      toast({ title: t('WebhooksPage.toast.error'), description: t('WebhooksPage.toast.deleteFailed', { detail: getApiErrorMessage(err, err.message) }), variant: 'destructive' });
    },
  });

  const testMutation = useMutation({
    mutationFn: (id: string) => webhooksApi.test(id),
    onSuccess: (response) => {
      const result = response.data;
      // Backend ``DeliveryStatus`` enum is ``delivered|failed|pending|retrying``;
      // there is no ``sent`` value. Previously the toast always showed
      // "Test webhook failed" even on success.
      if (result.status === 'delivered') {
        toast({ title: t('WebhooksPage.toast.success'), description: t('WebhooksPage.toast.testDelivered', { status: result.response_status ?? '?', time: result.response_time_ms ?? '?' }) });
      } else {
        toast({ title: t('WebhooksPage.toast.error'), description: t('WebhooksPage.toast.testFailed', { status: result.status, error: result.error || t('WebhooksPage.toast.unknownError') }), variant: 'destructive' });
      }
      queryClient.invalidateQueries({ queryKey: ['webhooks'] });
    },
    onError: (err: any) => {
      toast({ title: t('WebhooksPage.toast.error'), description: t('WebhooksPage.toast.testRequestFailed', { detail: getApiErrorMessage(err, err.message) }), variant: 'destructive' });
    },
  });

  // Filter
  const webhooks = allWebhooks.filter((w) => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matches =
        w.name.toLowerCase().includes(q) ||
        w.url.toLowerCase().includes(q) ||
        (w.description ?? '').toLowerCase().includes(q);
      if (!matches) return false;
    }
    if (statusFilter === 'enabled' && !w.enabled) return false;
    if (statusFilter === 'disabled' && w.enabled) return false;
    if (statusFilter === 'failing' && w.failure_count === 0) return false;
    return true;
  });

  // Stats
  const stats = {
    total: serverTotal,
    enabled: allWebhooks.filter((w) => w.enabled).length,
    failing: allWebhooks.filter((w) => w.failure_count > 0).length,
    deliveries: allWebhooks.reduce((sum, w) => sum + (w.success_count || 0), 0),
  };

  const hasActiveFilters = searchQuery !== '' || statusFilter !== 'all';
  const handleClearFilters = () => {
    setSearchQuery('');
    setStatusFilter('all');
  };

  // ── Bulk actions ──
  // Loop the existing per-row mutations over the selection with
  // Promise.allSettled so one failure never blocks the rest, then surface a
  // single summary toast. Per-row mutations already raise their own
  // destructive toast on individual failures, so this avoids false success.
  const summarize = (titleKey: string, failed: number) => {
    if (failed === 0) {
      // Title carries the action label; description reuses the generic
      // success string (count summary keys don't exist in this namespace).
      toast({ title: t(titleKey), description: t('WebhooksPage.toast.success') });
    } else {
      // Per-row failures already toasted individually; this is the honest
      // partial-failure summary (no fake success).
      toast({
        title: t(titleKey),
        description: t('WebhooksPage.toast.error'),
        variant: 'destructive',
      });
    }
  };

  const handleBulkTest = async () => {
    const targets = [...selectedWebhooks];
    const results = await Promise.allSettled(targets.map((w) => testMutation.mutateAsync(w.id)));
    const failed = results.filter((r) => r.status === 'rejected').length;
    summarize('WebhooksPage.bulk.test.title', failed);
    setSelectedWebhooks([]);
  };

  const handleBulkDisable = async () => {
    const targets = selectedWebhooks.filter((w) => w.enabled);
    const results = await Promise.allSettled(
      targets.map((w) => toggleMutation.mutateAsync({ id: w.id, enabled: false })),
    );
    const failed = results.filter((r) => r.status === 'rejected').length;
    summarize('WebhooksPage.bulk.disable.title', failed);
    setSelectedWebhooks([]);
  };

  const handleBulkDelete = async () => {
    if (!confirm(t('WebhooksPage.actions.deleteConfirm'))) return;
    const targets = [...selectedWebhooks];
    const results = await Promise.allSettled(targets.map((w) => deleteMutation.mutateAsync(w.id)));
    const failed = results.filter((r) => r.status === 'rejected').length;
    summarize('WebhooksPage.bulk.delete.title', failed);
    setSelectedWebhooks([]);
  };

  // Client-side CSV export of the currently filtered rows.
  const handleExport = () => {
    const rows = webhooks;
    if (rows.length === 0) return;
    const headers = ['name', 'url', 'enabled', 'event_types', 'success_count', 'failure_count', 'last_triggered'];
    const escape = (v: unknown) => {
      const s = v == null ? '' : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const lines = [
      headers.join(','),
      ...rows.map((w) =>
        [
          w.name,
          w.url,
          w.enabled,
          (w.event_types ?? []).join('; '),
          w.success_count,
          w.failure_count,
          w.last_triggered ?? '',
        ]
          .map(escape)
          .join(','),
      ),
    ];
    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `webhooks-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Columns
  const columns: DataTableColumn<Webhook>[] = [
    {
      id: 'name',
      header: t('WebhooksPage.columns.webhook'),
      accessorKey: 'name',
      cell: (w) => (
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-muted flex-shrink-0">
            <WebhookIcon className="h-4 w-4 text-muted-foreground" />
          </div>
          <div className="min-w-0">
            <div className="font-medium truncate">{w.name}</div>
            <div className="text-xs text-muted-foreground font-mono truncate">{w.url}</div>
          </div>
        </div>
      ),
    },
    {
      id: 'status',
      header: t('WebhooksPage.columns.status'),
      accessorFn: (w) => (w.enabled ? 'enabled' : 'disabled'),
      cell: (w) => (
        <StatusBadge variant={w.enabled ? 'success' : 'disabled'}>
          {w.enabled ? t('WebhooksPage.status.enabled') : t('WebhooksPage.status.disabled')}
        </StatusBadge>
      ),
    },
    {
      id: 'events',
      header: t('WebhooksPage.columns.events'),
      accessorFn: (w) => w.event_types.length,
      cell: (w) => (
        <span className="text-sm text-muted-foreground">
          {w.event_types.length === 0
            ? t('WebhooksPage.events.all')
            : w.event_types.length === 1
              ? t('WebhooksPage.events.typeOne', { count: w.event_types.length })
              : t('WebhooksPage.events.typeOther', { count: w.event_types.length })}
        </span>
      ),
    },
    {
      id: 'success',
      header: t('WebhooksPage.columns.successful'),
      accessorFn: (w) => w.success_count,
      cell: (w) => (
        <span className="text-sm font-medium tabular-nums text-success">{w.success_count}</span>
      ),
    },
    {
      id: 'failures',
      header: t('WebhooksPage.columns.failures'),
      accessorFn: (w) => w.failure_count,
      cell: (w) => (
        <span
          className={`text-sm font-medium tabular-nums ${
            w.failure_count > 0 ? 'text-destructive' : 'text-muted-foreground'
          }`}
        >
          {w.failure_count}
        </span>
      ),
    },
    {
      id: 'last',
      header: t('WebhooksPage.columns.lastTriggered'),
      accessorFn: (w) => w.last_triggered ?? '',
      cell: (w) => (
        <span className="text-xs text-muted-foreground">
          {w.last_triggered ? new Date(w.last_triggered).toLocaleString() : t('WebhooksPage.never')}
        </span>
      ),
    },
    {
      id: 'enabled',
      header: t('WebhooksPage.columns.active'),
      sortable: false,
      cell: (w) => (
        <Switch
          checked={w.enabled}
          onCheckedChange={(checked) => toggleMutation.mutate({ id: w.id, enabled: checked })}
        />
      ),
    },
    {
      id: 'actions',
      header: '',
      sortable: false,
      cell: (w) => (
        <div className="flex justify-end" onClick={(e) => e.stopPropagation()}>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={t('WebhooksPage.actions.menuLabel', { name: w.name })}>
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => testMutation.mutate(w.id)}>
                <FlaskConical className="h-4 w-4 mr-2" />
                {t('WebhooksPage.actions.test')}
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setViewDeliveriesId(w.id)}>
                <ClipboardList className="h-4 w-4 mr-2" />
                {t('WebhooksPage.actions.viewDeliveries')}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={() => {
                  if (confirm(t('WebhooksPage.actions.deleteConfirm'))) {
                    deleteMutation.mutate(w.id);
                  }
                }}
                className="text-destructive focus:text-destructive"
              >
                <Trash2 className="h-4 w-4 mr-2" />
                {t('WebhooksPage.actions.delete')}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      ),
    },
  ];

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader
          title={t('WebhooksPage.header.title')}
          description={t('WebhooksPage.header.description')}
          icon={WebhookIcon}
        />
        <ErrorState
          message={getApiErrorMessage(error, t('WebhooksPage.errorState.message'))}
          onRetry={() => refetch()}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        title={t('WebhooksPage.header.title')}
        description={t('WebhooksPage.header.description')}
        icon={WebhookIcon}
        onRefresh={() => refetch()}
        refreshing={isFetching}
        secondaryActions={[
          { label: t('WebhooksPage.header.export'), icon: Download, onClick: handleExport },
        ]}
        primaryAction={{
          label: t('WebhooksPage.header.addWebhook'),
          icon: Plus,
          onClick: () => setShowCreateModal(true),
        }}
      />

      {/* Stats */}
      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          {
            title: t('WebhooksPage.stats.total.title'),
            value: stats.total,
            icon: WebhookIcon,
            variant: 'default',
            description: t('WebhooksPage.stats.total.description'),
          },
          {
            title: t('WebhooksPage.stats.enabled.title'),
            value: stats.enabled,
            icon: CheckCircle,
            variant: 'success',
            description:
              stats.total > 0
                ? t('WebhooksPage.stats.enabled.active', { percent: Math.round((stats.enabled / stats.total) * 100) })
                : t('WebhooksPage.stats.enabled.none'),
          },
          {
            title: t('WebhooksPage.stats.failing.title'),
            value: stats.failing,
            icon: XCircle,
            variant: stats.failing > 0 ? 'destructive' : 'default',
            description: t('WebhooksPage.stats.failing.description'),
          },
          {
            title: t('WebhooksPage.stats.deliveries.title'),
            value: stats.deliveries,
            icon: ClipboardList,
            variant: 'info',
            description: t('WebhooksPage.stats.deliveries.description'),
          },
        ]}
      />

      {/* Toolbar */}
      <PageToolbar>
        <SearchBar
          value={searchQuery}
          onChange={setSearchQuery}
          placeholder={t('WebhooksPage.toolbar.searchPlaceholder')}
          className="w-full sm:w-auto"
        />
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-full sm:w-[160px]">
            <SelectValue placeholder={t('WebhooksPage.toolbar.allStatuses')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('WebhooksPage.toolbar.allStatuses')}</SelectItem>
            <SelectItem value="enabled">{t('WebhooksPage.status.enabled')}</SelectItem>
            <SelectItem value="disabled">{t('WebhooksPage.status.disabled')}</SelectItem>
            <SelectItem value="failing">{t('WebhooksPage.toolbar.failing')}</SelectItem>
          </SelectContent>
        </Select>
        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={handleClearFilters}>
            {t('WebhooksPage.toolbar.clearFilters')}
          </Button>
        )}
      </PageToolbar>

      {/* Table */}
      <DataTable
        data={webhooks}
        columns={columns}
        isLoading={isLoading}
        selectable
        onSelectionChange={setSelectedWebhooks}
        searchable={false}
        itemName={t('WebhooksPage.itemNamePlural')}
        getRowId={(w) => w.id}
      />

      {/* Bulk actions */}
      <BulkActionsBar
        selectedCount={selectedWebhooks.length}
        itemName={t('WebhooksPage.itemName')}
        onClear={() => setSelectedWebhooks([])}
        actions={[
          {
            label: t('WebhooksPage.bulk.test.label'),
            icon: FlaskConical,
            onClick: () => handleBulkTest(),
          },
          {
            label: t('WebhooksPage.bulk.disable.label'),
            icon: Power,
            onClick: () => handleBulkDisable(),
          },
          {
            label: t('WebhooksPage.bulk.delete.label'),
            icon: Trash2,
            variant: 'destructive',
            onClick: () => handleBulkDelete(),
          },
        ]}
      />

      {/* Create Modal */}
      <CreateWebhookModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        onCreate={(data) => createMutation.mutateAsync(data)}
      />

      {/* Deliveries Modal */}
      <DeliveriesModal
        webhookId={viewDeliveriesId}
        onClose={() => setViewDeliveriesId(null)}
      />
    </div>
  );
}
