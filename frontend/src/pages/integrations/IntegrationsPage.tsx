// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Integrations Hub Page
 *
 * Guided, typed integration connections (n8n, Slack, PagerDuty, etc.)
 * backed by the Webhook delivery engine.
 *
 * Each Integration owns one underlying Webhook record. Delivery history
 * and Dead-Letter Queue re-use the existing webhook sub-endpoints.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */
import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';
import { PageHeader, PageToolbar } from '@/components/layout';
import { useToast } from '@/hooks/use-toast';
import {
  integrationsApi,
  webhooksApi,
  Integration,
  IntegrationTemplate,
  getApiErrorMessage,
} from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Checkbox } from '@/components/ui/checkbox';
import { Skeleton } from '@/components/ui/skeleton';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { SearchBar } from '@/components/ui/search-bar';
import { StatsGrid } from '@/components/ui/stats-grid';
import { StatusBadge, type StatusVariant } from '@/components/ui/status-indicator';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { ErrorState } from '@/components/ui/empty-state';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { WizardDialog, type WizardStep } from '@/components/ui/wizard-dialog';
import {
  FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage,
} from '@/components/ui/form';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Plug,
  Plus,
  MoreHorizontal,
  FlaskConical,
  ClipboardList,
  Trash2,
  Loader2,
  Check,
  AlertCircle,
  Workflow,
  MessageSquare,
  Bell,
  TicketCheck,
  Webhook as WebhookIcon,
  Globe,
  RefreshCw,
  SkipForward,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Power,
  Download,
} from 'lucide-react';

// ─── Test result shape (J-6: was typed as `any`) ─────────────────────────────

interface TestResult {
  status: string;
  delivery_id?: string;
  response_code?: number;
  response_time_ms?: number;
  error?: string;
}

// ─── Icon map for integration types ──────────────────────────────────────────

const TYPE_ICONS: Record<string, React.ReactNode> = {
  n8n: <Workflow className="h-6 w-6" />,
  slack: <MessageSquare className="h-6 w-6" />,
  teams: <MessageSquare className="h-6 w-6" />,
  pagerduty: <Bell className="h-6 w-6" />,
  jira: <TicketCheck className="h-6 w-6" />,
  servicenow: <TicketCheck className="h-6 w-6" />,
  webhook: <WebhookIcon className="h-6 w-6" />,
};

const TYPE_COLORS: Record<string, string> = {
  n8n: 'text-orange-600 bg-orange-500/10',
  slack: 'text-purple-600 bg-purple-500/10',
  teams: 'text-blue-600 bg-blue-500/10',
  pagerduty: 'text-green-600 bg-green-500/10',
  jira: 'text-blue-700 bg-blue-600/10',
  servicenow: 'text-emerald-600 bg-emerald-500/10',
  webhook: 'text-muted-foreground bg-muted-foreground/10',
};

// ─── Status badge styles for delivery history modal ──────────────────────────

const statusStyle: Record<string, string> = {
  delivered: 'bg-success/10 text-success',
  failed: 'bg-destructive/10 text-destructive',
  pending: 'bg-warning/10 text-warning',
  retrying: 'bg-info/10 text-info',
};

// ─── Setup Wizard ─────────────────────────────────────────────────────────────
//
// Built on the canonical WizardDialog primitive.
//
// Steps:
//   1. "Choose type"     · RadioGroup of available integration types
//   2. "Configure"       · name, url, secret, description, verify_ssl
//   3. "Select events"   · multi-checkbox grid with per-category select-all
//   successContent       · post-submit success view with "Send Test Event"
//
// The createdIntegration (returned by integrationsApi.create) is stashed in
// component state during onSubmit so the successContent render-prop can use
// it for the test-event button.

interface SetupWizardProps {
  isOpen: boolean;
  onClose: () => void;
  onCreated: () => void;
}

type TFunc = (key: string, opts?: Record<string, unknown>) => string;

const buildSetupSchema = (t: TFunc) =>
  z.object({
    type: z.string().min(1, t('IntegrationsPage.validation.typeRequired')),
    name: z.string().min(1, t('IntegrationsPage.validation.nameRequired')),
    // Backend rejects non-HTTPS endpoints (integrations.py:154-156), so require
    // https:// client-side to avoid an avoidable 422 round-trip. Reuses the
    // existing urlInvalid message (no HTTPS-specific key exists).
    url: z
      .string()
      .url(t('IntegrationsPage.validation.urlInvalid'))
      .refine((v) => v.startsWith('https://'), t('IntegrationsPage.validation.urlInvalid')),
    secret: z.string().optional(),
    description: z.string().optional(),
    verify_ssl: z.boolean(),
    events: z.array(z.string()),
  });

type SetupValues = z.infer<ReturnType<typeof buildSetupSchema>>;

const SETUP_DEFAULTS: SetupValues = {
  type: '',
  name: '',
  url: '',
  secret: '',
  description: '',
  verify_ssl: true,
  events: [],
};

const SetupWizard: React.FC<SetupWizardProps> = ({ isOpen, onClose, onCreated }) => {
  const { t } = useTranslation('integrations');
  const setupSchema = buildSetupSchema(t);
  const { toast } = useToast();
  const [createdIntegration, setCreatedIntegration] = useState<Integration | null>(null);
  // Test-event ephemeral state for the success view.
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [isTesting, setIsTesting] = useState(false);

  const { data: typesData, isLoading: typesLoading } = useQuery({
    queryKey: ['integration-types'],
    queryFn: async () => (await integrationsApi.getTypes()).data,
    enabled: isOpen,
  });

  const { data: categoriesData, isLoading: categoriesLoading } = useQuery({
    queryKey: ['event-categories'],
    queryFn: async () => (await integrationsApi.getEventCategories()).data,
    enabled: isOpen,
  });

  const handleOpenChange = (next: boolean) => {
    if (!next) {
      // Reset our local ephemeral state on close. WizardDialog handles its
      // own form-state reset on next open.
      setCreatedIntegration(null);
      setTestResult(null);
      setIsTesting(false);
      onClose();
    }
  };

  const handleTest = async () => {
    if (!createdIntegration) return;
    try {
      setIsTesting(true);
      setTestResult(null);
      const res = await integrationsApi.test(createdIntegration.id);
      setTestResult(res.data);
    } catch (err: unknown) {
      setTestResult({ status: 'error', error: getApiErrorMessage(err) });
    } finally {
      setIsTesting(false);
    }
  };

  const types = typesData?.types ?? [];
  const categories = categoriesData?.categories ?? [];

  const steps: WizardStep<SetupValues>[] = [
    {
      id: 'type',
      label: t('IntegrationsPage.wizard.steps.type'),
      fields: ['type'],
      content: (form) => (
        <FormField
          control={form.control}
          name="type"
          render={({ field }) => (
            <FormItem>
              {typesLoading ? (
                <div className="grid grid-cols-2 gap-3">
                  {[...Array(6)].map((_, i) => (
                    <Skeleton key={i} className="h-24 w-full rounded-xl" />
                  ))}
                </div>
              ) : (
                <div className="grid grid-cols-2 gap-3">
                  {types.map((t) => {
                    const isSelected = field.value === t.id;
                    return (
                      <button
                        key={t.id}
                        type="button"
                        onClick={() => {
                          field.onChange(t.id);
                          // Pre-fill name + default events when a type is chosen.
                          if (!form.getValues('name')) {
                            form.setValue('name', t.label);
                          }
                          form.setValue('events', t.default_events ?? []);
                        }}
                        className={`flex items-start space-x-3 p-4 rounded-xl border text-left transition-all group ${
                          isSelected
                            ? 'border-primary bg-primary/5 ring-1 ring-primary'
                            : 'border-border hover:border-primary hover:bg-primary/5'
                        }`}
                      >
                        <div
                          className={`rounded-lg p-2 flex-shrink-0 ${
                            TYPE_COLORS[t.id] ?? TYPE_COLORS.webhook
                          }`}
                        >
                          {TYPE_ICONS[t.id] ?? <Globe className="h-6 w-6" />}
                        </div>
                        <div>
                          <p className="font-medium text-foreground group-hover:text-primary text-sm">
                            {t.label}
                          </p>
                          <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">
                            {t.description}
                          </p>
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}
              <FormMessage />
            </FormItem>
          )}
        />
      ),
    },
    {
      id: 'configure',
      label: t('IntegrationsPage.wizard.steps.configure'),
      fields: ['name', 'url', 'secret', 'description', 'verify_ssl'],
      content: (form) => {
        const selectedTypeId = form.watch('type');
        const selectedType = types.find((t) => t.id === selectedTypeId);
        return (
          <div className="space-y-4">
            {selectedType && (
              <div
                className={`flex items-center space-x-3 p-3 rounded-lg ${
                  TYPE_COLORS[selectedType.id] ?? TYPE_COLORS.webhook
                }`}
              >
                {TYPE_ICONS[selectedType.id] ?? <Globe className="h-5 w-5" />}
                <div>
                  <p className="font-medium text-sm">{selectedType.label}</p>
                  <p className="text-xs text-muted-foreground">{selectedType.description}</p>
                </div>
              </div>
            )}

            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('IntegrationsPage.wizard.fields.name.label')}</FormLabel>
                  <FormControl>
                    <Input
                      placeholder={
                        selectedType
                          ? t('IntegrationsPage.wizard.fields.name.placeholderTyped', { type: selectedType.label })
                          : t('IntegrationsPage.wizard.fields.name.placeholder')
                      }
                      {...field}
                    />
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
                  <FormLabel>{t('IntegrationsPage.wizard.fields.url.label')}</FormLabel>
                  <FormControl>
                    <Input
                      type="url"
                      placeholder="https://your-endpoint.example.com/webhook"
                      {...field}
                    />
                  </FormControl>
                  <FormDescription>
                    {selectedType?.id === 'n8n'
                      ? t('IntegrationsPage.wizard.fields.url.descN8n')
                      : selectedType?.id === 'slack'
                      ? t('IntegrationsPage.wizard.fields.url.descSlack')
                      : selectedType?.id === 'pagerduty'
                      ? t('IntegrationsPage.wizard.fields.url.descPagerduty')
                      : t('IntegrationsPage.wizard.fields.url.descDefault')}
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="secret"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('IntegrationsPage.wizard.fields.secret.label')}</FormLabel>
                  <FormControl>
                    <Input
                      type="password"
                      placeholder={t('IntegrationsPage.wizard.fields.secret.placeholder')}
                      {...field}
                    />
                  </FormControl>
                  <FormDescription>
                    {t('IntegrationsPage.wizard.fields.secret.descPrefix')}{' '}
                    <code className="text-xs bg-muted px-1 rounded">X-FreeSDN-Signature</code>{' '}
                    {t('IntegrationsPage.wizard.fields.secret.descSuffix')}
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="description"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('IntegrationsPage.wizard.fields.description.label')}</FormLabel>
                  <FormControl>
                    <Input placeholder={t('IntegrationsPage.wizard.fields.description.placeholder')} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="verify_ssl"
              render={({ field }) => (
                <FormItem>
                  <div className="flex items-center space-x-2">
                    <Checkbox
                      id="verify-ssl"
                      checked={field.value}
                      onCheckedChange={(c) => field.onChange(!!c)}
                    />
                    <Label htmlFor="verify-ssl" className="cursor-pointer">
                      {t('IntegrationsPage.wizard.fields.verifySsl.label')}
                    </Label>
                  </div>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>
        );
      },
    },
    {
      id: 'events',
      label: t('IntegrationsPage.wizard.steps.events'),
      fields: ['events'],
      content: (form) => {
        const selectedEvents = form.watch('events') ?? [];
        const name = form.watch('name');
        const selectedTypeId = form.watch('type');
        const selectedType = types.find((t) => t.id === selectedTypeId);
        const toggleEvent = (evt: string) => {
          const next = selectedEvents.includes(evt)
            ? selectedEvents.filter((e) => e !== evt)
            : [...selectedEvents, evt];
          form.setValue('events', next, { shouldDirty: true });
        };
        const toggleCategory = (events: string[]) => {
          const allSelected = events.every((e) => selectedEvents.includes(e));
          const next = allSelected
            ? selectedEvents.filter((e) => !events.includes(e))
            : Array.from(new Set([...selectedEvents, ...events]));
          form.setValue('events', next, { shouldDirty: true });
        };

        return (
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              {t('IntegrationsPage.wizard.events.choosePrefix')} <strong>{name}</strong>.{' '}
              {selectedType?.default_events?.length
                ? t('IntegrationsPage.wizard.events.defaultsPreselected')
                : ''}
            </p>

            {categoriesLoading ? (
              <div className="space-y-3">
                <Skeleton className="h-24 w-full" />
                <Skeleton className="h-24 w-full" />
              </div>
            ) : (
              <div className="space-y-4 max-h-64 overflow-y-auto pr-1">
                {categories.map((cat) => {
                  const allSelected = cat.events.every((e) => selectedEvents.includes(e));
                  return (
                    <div key={cat.name} className="space-y-2">
                      <div className="flex items-center space-x-2">
                        <Checkbox
                          id={`cat-${cat.name}`}
                          checked={allSelected}
                          onCheckedChange={() => toggleCategory(cat.events)}
                        />
                        <Label
                          htmlFor={`cat-${cat.name}`}
                          className="font-medium text-sm cursor-pointer"
                        >
                          {cat.name}
                        </Label>
                      </div>
                      <div className="ml-6 grid grid-cols-1 gap-1">
                        {cat.events.map((evt) => (
                          <div key={evt} className="flex items-center space-x-2">
                            <Checkbox
                              id={evt}
                              checked={selectedEvents.includes(evt)}
                              onCheckedChange={() => toggleEvent(evt)}
                            />
                            <Label
                              htmlFor={evt}
                              className="text-xs font-mono cursor-pointer text-muted-foreground"
                            >
                              {evt}
                            </Label>
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {selectedEvents.length > 0 && (
              <p className="text-xs text-muted-foreground">
                {selectedEvents.length > 1
                  ? t('IntegrationsPage.wizard.events.selectedCountPlural', { count: selectedEvents.length })
                  : t('IntegrationsPage.wizard.events.selectedCount', { count: selectedEvents.length })}
              </p>
            )}
          </div>
        );
      },
    },
  ];

  return (
    <WizardDialog<SetupValues>
      open={isOpen}
      onOpenChange={handleOpenChange}
      title={t('IntegrationsPage.wizard.title')}
      description={t('IntegrationsPage.wizard.description')}
      schema={setupSchema}
      defaultValues={SETUP_DEFAULTS}
      steps={steps}
      submitLabel={t('IntegrationsPage.wizard.submit')}
      contentClassName="max-w-2xl max-h-[90vh] overflow-y-auto"
      onSubmit={async (values) => {
        try {
          const res = await integrationsApi.create({
            name: values.name,
            description: values.description || undefined,
            integration_type: values.type,
            url: values.url,
            secret: values.secret || undefined,
            event_subscriptions: values.events,
            verify_ssl: values.verify_ssl,
          });
          // Stash for the success view's "Send Test Event" button.
          setCreatedIntegration(res.data);
          onCreated();
        } catch (err: unknown) {
          // Surface a toast (preserves prior UX) AND re-throw so the wizard
          // shows the inline server-error banner on the final step.
          const e = err as any;
          toast({
            title: t('IntegrationsPage.toasts.createFailed'),
            description: e.response?.data?.detail || e.message,
            variant: 'destructive',
          });
          throw err;
        }
      }}
      successContent={() => {
        if (!createdIntegration) return null;
        return (
          <div className="space-y-4 text-center py-2">
            <div className="flex justify-center">
              <div className="h-14 w-14 rounded-full bg-green-500/10 flex items-center justify-center">
                <Check className="h-7 w-7 text-green-600" />
              </div>
            </div>
            <div>
              <h3 className="font-semibold text-foreground text-lg">
                {t('IntegrationsPage.wizard.success.heading', { name: createdIntegration.name })}
              </h3>
              <p className="text-sm text-muted-foreground mt-1">
                {t('IntegrationsPage.wizard.success.subtitle')}
              </p>
            </div>

            {testResult && (
              <div
                className={`text-left rounded-lg p-4 ${
                  testResult.status === 'delivered' || testResult.status === 'sent'
                    ? 'bg-green-500/10 border border-green-500/20'
                    : 'bg-destructive/10 border border-destructive/20'
                }`}
              >
                {testResult.status === 'delivered' || testResult.status === 'sent' ? (
                  <div className="flex items-start space-x-2">
                    <Check className="h-4 w-4 text-green-600 mt-0.5 flex-shrink-0" />
                    <div>
                      <p className="text-sm font-medium text-green-700 dark:text-green-400">
                        {t('IntegrationsPage.wizard.success.testDelivered')}
                      </p>
                      <p className="text-xs text-muted-foreground mt-1">
                        {t('IntegrationsPage.wizard.success.httpStats', {
                          code: testResult.response_code,
                          ms: testResult.response_time_ms,
                        })}
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-start space-x-2">
                    <AlertCircle className="h-4 w-4 text-destructive mt-0.5 flex-shrink-0" />
                    <div>
                      <p className="text-sm font-medium text-destructive">{t('IntegrationsPage.wizard.success.testFailed')}</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        {testResult.error || t('IntegrationsPage.common.unknownError')}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}

            <div className="flex justify-center">
              <Button variant="outline" onClick={handleTest} disabled={isTesting}>
                {isTesting ? (
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <FlaskConical className="h-4 w-4 mr-2" />
                )}
                {t('IntegrationsPage.actions.sendTestEvent')}
              </Button>
            </div>
          </div>
        );
      }}
      successCloseLabel={t('IntegrationsPage.wizard.success.closeLabel')}
    />
  );
};

// ─── Delivery History + DLQ Modal ─────────────────────────────────────────────

interface DeliveryHistoryModalProps {
  integrationId: string | null;
  webhookId: string | null;
  onClose: () => void;
}

const DeliveryHistoryModal: React.FC<DeliveryHistoryModalProps> = ({
  webhookId,
  onClose,
}) => {
  const { t } = useTranslation('integrations');
  const isOpen = !!webhookId;
  const [replayingId, setReplayingId] = useState<string | null>(null);
  const [replayingAll, setReplayingAll] = useState(false);
  const { toast } = useToast();

  const {
    data: deliveries,
    isLoading: deliveriesLoading,
    isError: deliveriesError,
    error: deliveriesErr,
    refetch: refetchDeliveries,
  } = useQuery({
    queryKey: ['deliveries', webhookId],
    queryFn: async () => {
      const res = await webhooksApi.getDeliveries(webhookId!, { per_page: 30 });
      return Array.isArray(res.data) ? res.data : (res.data as any)?.items ?? [];
    },
    enabled: isOpen,
  });

  const {
    data: dlqData,
    isLoading: dlqLoading,
    isError: dlqError,
    error: dlqErr,
    refetch: refetchDlq,
  } = useQuery({
    queryKey: ['dlq', webhookId],
    queryFn: async () => {
      const res = await integrationsApi.listDeadLetters(webhookId!, { per_page: 30 });
      return res.data;
    },
    enabled: isOpen,
  });

  const dlqItems = dlqData?.items ?? [];
  // J-5: Use total from API response, not page-item count (which is capped at per_page=30)
  const dlqUnreplayedTotal: number = dlqData?.total
    ? dlqItems.filter((d: any) => !d.replayed_at).length +
      Math.max(0, (dlqData.total - dlqItems.length))
    : dlqItems.filter((d: any) => !d.replayed_at).length;
  const hasUnreplayed = dlqItems.some((d: any) => !d.replayed_at) || dlqUnreplayedTotal > 0;

  const handleReplay = async (dlqId: string) => {
    if (!webhookId) return;
    try {
      setReplayingId(dlqId);
      await integrationsApi.replayDeadLetter(webhookId, dlqId);
      refetchDlq();
      refetchDeliveries();
    } catch (err: unknown) {
      toast({
        title: t('IntegrationsPage.toasts.replayFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    } finally {
      setReplayingId(null);
    }
  };

  const handleReplayAll = async () => {
    if (!webhookId) return;
    try {
      setReplayingAll(true);
      await integrationsApi.replayAllDeadLetters(webhookId);
      refetchDlq();
      refetchDeliveries();
    } catch (err: unknown) {
      toast({
        title: t('IntegrationsPage.toasts.replayAllFailed'),
        description: getApiErrorMessage(err),
        variant: 'destructive',
      });
    } finally {
      setReplayingAll(false);
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent className="max-w-3xl max-h-[80vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle>{t('IntegrationsPage.history.title')}</DialogTitle>
        </DialogHeader>

        <Tabs defaultValue="deliveries" className="flex-1 overflow-hidden flex flex-col">
          <TabsList className="w-full">
            <TabsTrigger value="deliveries" className="flex-1">{t('IntegrationsPage.history.tabs.deliveries')}</TabsTrigger>
            <TabsTrigger value="dlq" className="flex-1">
              {t('IntegrationsPage.history.tabs.dlq')}
              {dlqUnreplayedTotal > 0 && (
                <span className="ml-1.5 px-1.5 py-0.5 text-xs rounded-full bg-destructive/20 text-destructive font-medium">
                  {dlqUnreplayedTotal}
                </span>
              )}
            </TabsTrigger>
          </TabsList>

          {/* Deliveries tab */}
          <TabsContent value="deliveries" className="flex-1 overflow-y-auto mt-0">
            {deliveriesLoading ? (
              <div className="space-y-3 p-1">
                {[...Array(5)].map((_, i) => <Skeleton key={i} className="h-16 w-full" />)}
              </div>
            ) : deliveriesError ? (
              <ErrorState
                message={getApiErrorMessage(deliveriesErr) || t('IntegrationsPage.errors.loadFailed')}
                onRetry={() => refetchDeliveries()}
              />
            ) : !deliveries?.length ? (
              <div className="text-center text-muted-foreground py-10">{t('IntegrationsPage.history.noDeliveries')}</div>
            ) : (
              <div className="space-y-2 p-1">
                {deliveries.map((d: any) => (
                  <div key={d.id} className="p-3 bg-muted/50 rounded-lg">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span
                          className={`px-2 py-0.5 text-xs font-medium rounded ${statusStyle[d.status] || 'bg-muted text-muted-foreground'}`}
                        >
                          {d.status}
                        </span>
                        <span className="text-xs text-muted-foreground font-mono">{d.event_type}</span>
                        <span className="text-xs text-muted-foreground">{t('IntegrationsPage.history.attempt', { n: d.attempt_number })}</span>
                      </div>
                      <span className="text-xs text-muted-foreground">
                        {new Date(d.created_at).toLocaleString()}
                      </span>
                    </div>
                    {d.response_code && (
                      <p className="text-xs text-muted-foreground mt-1">
                        {t('IntegrationsPage.history.http', { code: d.response_code })}
                        {d.response_time_ms ? ` · ${d.response_time_ms}ms` : ''}
                      </p>
                    )}
                    {d.error_message && (
                      <p className="text-xs text-destructive mt-1 line-clamp-1">{d.error_message}</p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </TabsContent>

          {/* Dead-Letter Queue tab */}
          <TabsContent value="dlq" className="flex-1 overflow-y-auto mt-0">
            {dlqItems.length > 0 && hasUnreplayed && (
              <div className="flex justify-end mb-2 px-1">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleReplayAll}
                  disabled={replayingAll}
                >
                  {replayingAll ? (
                    <Loader2 className="h-3 w-3 mr-1.5 animate-spin" />
                  ) : (
                    <RefreshCw className="h-3 w-3 mr-1.5" />
                  )}
                  {t('IntegrationsPage.actions.replayAll')}
                </Button>
              </div>
            )}

            {dlqLoading ? (
              <div className="space-y-3 p-1">
                {[...Array(3)].map((_, i) => <Skeleton key={i} className="h-20 w-full" />)}
              </div>
            ) : dlqError ? (
              <ErrorState
                message={getApiErrorMessage(dlqErr) || t('IntegrationsPage.errors.loadFailed')}
                onRetry={() => refetchDlq()}
              />
            ) : dlqItems.length === 0 ? (
              <div className="text-center text-muted-foreground py-10">
                <Check className="h-8 w-8 mx-auto mb-2 text-green-500" />
                {t('IntegrationsPage.history.dlqEmpty')}
              </div>
            ) : (
              <div className="space-y-2 p-1">
                {dlqItems.map((d: any) => (
                  <div key={d.id} className="p-3 bg-muted/50 rounded-lg border border-destructive/10">
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="flex items-center space-x-2">
                          <AlertTriangle className="h-3.5 w-3.5 text-destructive flex-shrink-0" />
                          <span className="text-xs font-mono text-muted-foreground">{d.event_type}</span>
                          <span className="text-xs text-muted-foreground">{t('IntegrationsPage.history.attemptsCount', { n: d.attempt_count })}</span>
                        </div>
                        <p className="text-xs text-destructive mt-1 line-clamp-1">{d.failure_reason || t('IntegrationsPage.history.unknownFailure')}</p>
                        <p className="text-xs text-muted-foreground mt-0.5">
                          {t('IntegrationsPage.history.finalAttempt', { time: new Date(d.final_attempt_at).toLocaleString() })}
                        </p>
                        {d.replayed_at && (
                          <p className="text-xs text-green-600 mt-0.5">
                            {t('IntegrationsPage.history.replayed', { time: new Date(d.replayed_at).toLocaleString() })}
                          </p>
                        )}
                      </div>
                      {!d.replayed_at && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleReplay(d.id)}
                          disabled={replayingId === d.id}
                          className="flex-shrink-0 ml-2"
                        >
                          {replayingId === d.id ? (
                            <Loader2 className="h-3 w-3 animate-spin" />
                          ) : (
                            <SkipForward className="h-3 w-3" />
                          )}
                          <span className="ml-1 text-xs">{t('IntegrationsPage.actions.replay')}</span>
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
};

// ─── Template Picker ──────────────────────────────────────────────────────────
//
// Wires the previously-dead integrationsApi.getTemplates / applyTemplate pair.
// A preset gallery: pick a template, supply the (HTTPS) endpoint URL + optional
// secret, and apply. The backend pre-fills name/type/default events from the
// template, so the client only needs the URL.

interface TemplatePickerDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onApplied: () => void;
}

const TemplatePickerDialog: React.FC<TemplatePickerDialogProps> = ({ isOpen, onClose, onApplied }) => {
  const { t } = useTranslation('integrations');
  const { toast } = useToast();
  const [selected, setSelected] = useState<IntegrationTemplate | null>(null);
  const [url, setUrl] = useState('');
  const [secret, setSecret] = useState('');

  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['integration-templates'],
    queryFn: async () => (await integrationsApi.getTemplates()).data,
    enabled: isOpen,
  });

  const templates = data?.templates ?? [];

  const reset = () => {
    setSelected(null);
    setUrl('');
    setSecret('');
  };

  const applyMutation = useMutation({
    mutationFn: () =>
      integrationsApi.applyTemplate(selected!.id, { url: url.trim(), secret: secret.trim() || undefined }),
    onSuccess: () => {
      toast({ title: t('common:success') });
      reset();
      onApplied();
      onClose();
    },
    onError: (err: any) => {
      toast({
        title: t('IntegrationsPage.toasts.createFailed'),
        description: err.response?.data?.detail || err.message,
        variant: 'destructive',
      });
    },
  });

  const urlValid = /^https:\/\//.test(url.trim());

  return (
    <Dialog
      open={isOpen}
      onOpenChange={(open) => {
        if (!open) {
          reset();
          onClose();
        }
      }}
    >
      <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{t('IntegrationsPage.wizard.title')}</DialogTitle>
        </DialogHeader>

        {isLoading ? (
          <div className="grid grid-cols-2 gap-3">
            {[...Array(4)].map((_, i) => (
              <Skeleton key={i} className="h-20 w-full rounded-xl" />
            ))}
          </div>
        ) : isError ? (
          <ErrorState
            message={getApiErrorMessage(error) || t('IntegrationsPage.errors.loadFailed')}
            onRetry={() => refetch()}
          />
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-2">
              {templates.map((tmpl) => {
                const isSel = selected?.id === tmpl.id;
                return (
                  <button
                    key={tmpl.id}
                    type="button"
                    onClick={() => setSelected(tmpl)}
                    className={`flex items-start gap-3 rounded-xl border p-3 text-left transition-all ${
                      isSel
                        ? 'border-primary bg-primary/5 ring-1 ring-primary'
                        : 'border-border hover:border-primary hover:bg-primary/5'
                    }`}
                  >
                    <div
                      className={`rounded-lg p-2 flex-shrink-0 ${
                        TYPE_COLORS[tmpl.integration_type] ?? TYPE_COLORS.webhook
                      }`}
                    >
                      {TYPE_ICONS[tmpl.integration_type] ?? <Globe className="h-5 w-5" />}
                    </div>
                    <div className="min-w-0">
                      <p className="font-medium text-sm truncate">{tmpl.name}</p>
                      <p className="text-xs text-muted-foreground line-clamp-2">{tmpl.description}</p>
                    </div>
                  </button>
                );
              })}
            </div>

            {selected && (
              <div className="space-y-3 border-t pt-4">
                <div className="space-y-1.5">
                  <Label htmlFor="tmpl-url">{t('IntegrationsPage.wizard.fields.url.label')}</Label>
                  <Input
                    id="tmpl-url"
                    type="url"
                    placeholder="https://your-endpoint.example.com/webhook"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">
                    {t('IntegrationsPage.wizard.fields.url.descDefault')}
                  </p>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="tmpl-secret">{t('IntegrationsPage.wizard.fields.secret.label')}</Label>
                  <Input
                    id="tmpl-secret"
                    type="password"
                    autoComplete="new-password"
                    value={secret}
                    onChange={(e) => setSecret(e.target.value)}
                  />
                </div>
              </div>
            )}

            <div className="flex justify-end gap-2 pt-2">
              <Button variant="outline" onClick={() => { reset(); onClose(); }}>
                {t('common:cancel')}
              </Button>
              <Button
                onClick={() => applyMutation.mutate()}
                disabled={!selected || !urlValid || applyMutation.isPending}
              >
                {applyMutation.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                {t('common:apply')}
              </Button>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
};

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function IntegrationsPage() {
  const { t } = useTranslation('integrations');
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const [showWizard, setShowWizard] = useState(false);
  const [showTemplates, setShowTemplates] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selectedRows, setSelectedRows] = useState<Integration[]>([]);
  const [deliveryModal, setDeliveryModal] = useState<{
    integrationId: string;
    webhookId: string;
  } | null>(null);

  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ['integrations'],
    queryFn: async () => (await integrationsApi.list({ per_page: 50 })).data,
  });

  const allIntegrations: Integration[] = data?.items ?? [];

  const toggleMutation = useMutation({
    mutationFn: async ({ id, enabled }: { id: string; enabled: boolean }) =>
      enabled ? integrationsApi.enable(id) : integrationsApi.disable(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['integrations'] }),
    onError: (err: any) => {
      toast({
        title: t('IntegrationsPage.toasts.updateFailed'),
        description: err.response?.data?.detail || err.message,
        variant: 'destructive',
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => integrationsApi.delete(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['integrations'] }),
    onError: (err: any) => {
      toast({
        title: t('IntegrationsPage.toasts.deleteFailed'),
        description: err.response?.data?.detail || err.message,
        variant: 'destructive',
      });
    },
  });

  const testMutation = useMutation({
    mutationFn: (id: string) => integrationsApi.test(id),
    onSuccess: (res) => {
      const r: TestResult = res.data;
      if (r.status === 'delivered' || r.status === 'sent') {
        toast({
          title: t('IntegrationsPage.toasts.testDelivered'),
          description: t('IntegrationsPage.wizard.success.httpStats', {
            code: r.response_code,
            ms: r.response_time_ms,
          }),
        });
      } else {
        toast({ title: t('IntegrationsPage.toasts.testFailed'), description: r.error || t('IntegrationsPage.common.unknownError'), variant: 'destructive' });
      }
      queryClient.invalidateQueries({ queryKey: ['integrations'] });
    },
    onError: (err: any) => {
      toast({ title: t('IntegrationsPage.toasts.testFailed'), description: err.response?.data?.detail || err.message, variant: 'destructive' });
    },
  });

  const handleDelete = (id: string) => {
    if (!window.confirm(t('IntegrationsPage.confirm.delete'))) return;
    deleteMutation.mutate(id);
  };

  // ── Bulk actions ──
  // Loop the existing per-row mutations over the selection with
  // Promise.allSettled so one failure never blocks the rest, then surface a
  // single summary toast. Per-row mutations already raise their own
  // destructive toast on individual failures, so this avoids false success.
  const summarize = (titleKey: string, failed: number) => {
    if (failed === 0) {
      toast({ title: t(titleKey), description: t('common:success') });
    } else {
      toast({ title: t(titleKey), description: t('common:error'), variant: 'destructive' });
    }
  };

  const handleBulkTest = async () => {
    const targets = selectedRows.filter((i) => i.is_enabled);
    const results = await Promise.allSettled(targets.map((i) => testMutation.mutateAsync(i.id)));
    const failed = results.filter((r) => r.status === 'rejected').length;
    summarize('IntegrationsPage.bulk.test.title', failed);
    setSelectedRows([]);
  };

  const handleBulkDisable = async () => {
    const targets = selectedRows.filter((i) => i.is_enabled);
    const results = await Promise.allSettled(
      targets.map((i) => toggleMutation.mutateAsync({ id: i.id, enabled: false })),
    );
    const failed = results.filter((r) => r.status === 'rejected').length;
    summarize('IntegrationsPage.bulk.disable.title', failed);
    setSelectedRows([]);
  };

  const handleBulkDelete = async () => {
    if (!window.confirm(t('IntegrationsPage.confirm.delete'))) return;
    const targets = [...selectedRows];
    const results = await Promise.allSettled(targets.map((i) => deleteMutation.mutateAsync(i.id)));
    const failed = results.filter((r) => r.status === 'rejected').length;
    summarize('IntegrationsPage.bulk.delete.title', failed);
    setSelectedRows([]);
  };

  // Client-side CSV export of the currently filtered rows.
  const handleExport = () => {
    const rows = integrations;
    if (rows.length === 0) return;
    const headers = ['name', 'integration_type', 'is_enabled', 'events', 'deliveries_7d', 'last_delivery_status', 'last_delivery_at'];
    const escape = (v: unknown) => {
      const s = v == null ? '' : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const lines = [
      headers.join(','),
      ...rows.map((i) =>
        [
          i.name,
          i.integration_type,
          i.is_enabled,
          (i.event_subscriptions ?? []).join('; '),
          i.delivery_count_7d,
          i.last_delivery_status ?? '',
          i.last_delivery_at ?? '',
        ]
          .map(escape)
          .join(','),
      ),
    ];
    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `integrations-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Filter
  const integrations = allIntegrations.filter((i) => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matches =
        i.name.toLowerCase().includes(q) ||
        i.integration_type.toLowerCase().includes(q) ||
        (i.description ?? '').toLowerCase().includes(q);
      if (!matches) return false;
    }
    if (typeFilter !== 'all' && i.integration_type !== typeFilter) return false;
    if (statusFilter === 'enabled' && !i.is_enabled) return false;
    if (statusFilter === 'disabled' && i.is_enabled) return false;
    if (statusFilter === 'failing' && i.last_delivery_status !== 'failed') return false;
    return true;
  });

  // Stats
  const stats = {
    total: allIntegrations.length,
    enabled: allIntegrations.filter((i) => i.is_enabled).length,
    failing: allIntegrations.filter((i) => i.last_delivery_status === 'failed').length,
    deliveries7d: allIntegrations.reduce((sum, i) => sum + (i.delivery_count_7d || 0), 0),
  };

  const hasActiveFilters = searchQuery !== '' || typeFilter !== 'all' || statusFilter !== 'all';
  const handleClearFilters = () => {
    setSearchQuery('');
    setTypeFilter('all');
    setStatusFilter('all');
  };

  // Columns
  const columns: DataTableColumn<Integration>[] = [
    {
      id: 'name',
      header: t('IntegrationsPage.columns.integration'),
      accessorKey: 'name',
      cell: (i) => {
        const iconColorClass = TYPE_COLORS[i.integration_type] ?? TYPE_COLORS.webhook;
        const icon = TYPE_ICONS[i.integration_type] ?? <Globe className="h-5 w-5" />;
        return (
          <div className="flex items-center gap-3 min-w-0">
            <div className={`flex h-9 w-9 items-center justify-center rounded-lg flex-shrink-0 ${iconColorClass}`}>
              {icon}
            </div>
            <div className="min-w-0">
              <div className="font-medium truncate">{i.name}</div>
              <div className="text-xs text-muted-foreground capitalize truncate">
                {i.integration_type.replace('_', ' ')}
              </div>
            </div>
          </div>
        );
      },
    },
    {
      id: 'status',
      header: t('IntegrationsPage.columns.status'),
      accessorFn: (i) => (i.is_enabled ? 'enabled' : 'disabled'),
      cell: (i) => {
        const variant: StatusVariant = !i.is_enabled
          ? 'disabled'
          : i.last_delivery_status === 'failed'
            ? 'error'
            : 'success';
        const label = !i.is_enabled
          ? t('IntegrationsPage.status.disabled')
          : i.last_delivery_status === 'failed'
            ? t('IntegrationsPage.status.lastFailed')
            : t('IntegrationsPage.status.active');
        return <StatusBadge variant={variant}>{label}</StatusBadge>;
      },
    },
    {
      id: 'events',
      header: t('IntegrationsPage.columns.events'),
      accessorFn: (i) => i.event_subscriptions.length,
      cell: (i) => (
        <span className="text-sm text-muted-foreground">
          {i.event_subscriptions.length === 0
            ? t('IntegrationsPage.events.all')
            : i.event_subscriptions.length === 1
              ? t('IntegrationsPage.events.typeCount', { n: i.event_subscriptions.length })
              : t('IntegrationsPage.events.typeCountPlural', { n: i.event_subscriptions.length })}
        </span>
      ),
    },
    {
      id: 'deliveries',
      header: t('IntegrationsPage.columns.deliveries7d'),
      accessorFn: (i) => i.delivery_count_7d,
      cell: (i) => (
        <span className="text-sm font-medium tabular-nums">{i.delivery_count_7d}</span>
      ),
    },
    {
      id: 'rate',
      header: t('IntegrationsPage.columns.successRate'),
      accessorFn: (i) =>
        i.delivery_count_7d > 0 ? Math.round((i.success_count_7d / i.delivery_count_7d) * 100) : 0,
      cell: (i) => {
        const rate =
          i.delivery_count_7d > 0
            ? Math.round((i.success_count_7d / i.delivery_count_7d) * 100)
            : null;
        const tone =
          rate === null ? 'text-muted-foreground' : rate < 80 ? 'text-destructive' : 'text-success';
        return <span className={`text-sm font-medium tabular-nums ${tone}`}>{rate !== null ? `${rate}%` : '-'}</span>;
      },
    },
    {
      id: 'last',
      header: t('IntegrationsPage.columns.lastDelivery'),
      accessorFn: (i) => i.last_delivery_at ?? '',
      cell: (i) => (
        <span className="text-xs text-muted-foreground">
          {i.last_delivery_at ? new Date(i.last_delivery_at).toLocaleString() : t('IntegrationsPage.common.never')}
        </span>
      ),
    },
    {
      id: 'enabled',
      header: t('IntegrationsPage.columns.active'),
      sortable: false,
      cell: (i) => (
        <Switch
          checked={i.is_enabled}
          onCheckedChange={(checked) => toggleMutation.mutate({ id: i.id, enabled: checked })}
        />
      ),
    },
    {
      id: 'actions',
      header: '',
      sortable: false,
      cell: (i) => (
        <div className="flex justify-end" onClick={(e) => e.stopPropagation()}>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={t('IntegrationsPage.actions.menuFor', { name: i.name })}>
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem
                onClick={() => testMutation.mutate(i.id)}
                disabled={!i.is_enabled}
              >
                <FlaskConical className="h-4 w-4 mr-2" />
                {t('IntegrationsPage.actions.sendTestEvent')}
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => setDeliveryModal({ integrationId: i.id, webhookId: i.webhook_id })}>
                <ClipboardList className="h-4 w-4 mr-2" />
                {t('IntegrationsPage.actions.deliveryHistory')}
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={() => handleDelete(i.id)}
                className="text-destructive focus:text-destructive"
              >
                <Trash2 className="h-4 w-4 mr-2" />
                {t('IntegrationsPage.actions.delete')}
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
          title={t('IntegrationsPage.header.title')}
          description={t('IntegrationsPage.header.description')}
          icon={Plug}
        />
        <ErrorState
          message={(error as any).response?.data?.detail || t('IntegrationsPage.errors.loadFailed')}
          onRetry={() => refetch()}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={t('IntegrationsPage.header.title')}
        description={t('IntegrationsPage.header.description')}
        icon={Plug}
        onRefresh={() => refetch()}
        refreshing={isFetching}
        secondaryActions={[
          { label: t('IntegrationsPage.wizard.steps.type'), icon: Workflow, onClick: () => setShowTemplates(true) },
          { label: t('IntegrationsPage.actions.export'), icon: Download, onClick: handleExport },
        ]}
        primaryAction={{
          label: t('IntegrationsPage.actions.addIntegration'),
          icon: Plus,
          onClick: () => setShowWizard(true),
        }}
      />

      {/* Stats */}
      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          {
            title: t('IntegrationsPage.stats.total.title'),
            value: stats.total,
            icon: Plug,
            variant: 'default',
            description: t('IntegrationsPage.stats.total.description'),
          },
          {
            title: t('IntegrationsPage.stats.enabled.title'),
            value: stats.enabled,
            icon: CheckCircle,
            variant: 'success',
            description:
              stats.total > 0
                ? t('IntegrationsPage.stats.enabled.descriptionActive', {
                    pct: Math.round((stats.enabled / stats.total) * 100),
                  })
                : t('IntegrationsPage.stats.enabled.descriptionNone'),
          },
          {
            title: t('IntegrationsPage.stats.failing.title'),
            value: stats.failing,
            icon: XCircle,
            variant: stats.failing > 0 ? 'destructive' : 'default',
            description: t('IntegrationsPage.stats.failing.description'),
          },
          {
            title: t('IntegrationsPage.stats.deliveries7d.title'),
            value: stats.deliveries7d,
            icon: ClipboardList,
            variant: 'info',
            description: t('IntegrationsPage.stats.deliveries7d.description'),
          },
        ]}
      />

      {/* Toolbar */}
      <PageToolbar>
        <SearchBar
          value={searchQuery}
          onChange={setSearchQuery}
          placeholder={t('IntegrationsPage.toolbar.searchPlaceholder')}
          className="w-full sm:w-auto"
        />
        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-full sm:w-[160px]">
            <SelectValue placeholder={t('IntegrationsPage.toolbar.allTypes')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('IntegrationsPage.toolbar.allTypes')}</SelectItem>
            <SelectItem value="n8n">n8n</SelectItem>
            <SelectItem value="slack">Slack</SelectItem>
            <SelectItem value="teams">Teams</SelectItem>
            <SelectItem value="pagerduty">PagerDuty</SelectItem>
            <SelectItem value="jira">Jira</SelectItem>
            <SelectItem value="servicenow">ServiceNow</SelectItem>
            <SelectItem value="webhook">Webhook</SelectItem>
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-full sm:w-[160px]">
            <SelectValue placeholder={t('IntegrationsPage.toolbar.allStatuses')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('IntegrationsPage.toolbar.allStatuses')}</SelectItem>
            <SelectItem value="enabled">{t('IntegrationsPage.toolbar.statusEnabled')}</SelectItem>
            <SelectItem value="disabled">{t('IntegrationsPage.toolbar.statusDisabled')}</SelectItem>
            <SelectItem value="failing">{t('IntegrationsPage.toolbar.statusFailing')}</SelectItem>
          </SelectContent>
        </Select>
        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={handleClearFilters}>
            {t('IntegrationsPage.toolbar.clearFilters')}
          </Button>
        )}
      </PageToolbar>

      {/* Table */}
      <DataTable
        data={integrations}
        columns={columns}
        isLoading={isLoading}
        selectable
        onSelectionChange={setSelectedRows}
        searchable={false}
        itemName={t('IntegrationsPage.itemNamePlural')}
        getRowId={(i) => i.id}
      />

      {/* Bulk actions */}
      <BulkActionsBar
        selectedCount={selectedRows.length}
        itemName={t('IntegrationsPage.itemName')}
        onClear={() => setSelectedRows([])}
        actions={[
          {
            label: t('IntegrationsPage.bulk.test.label'),
            icon: FlaskConical,
            onClick: () => handleBulkTest(),
          },
          {
            label: t('IntegrationsPage.bulk.disable.label'),
            icon: Power,
            onClick: () => handleBulkDisable(),
          },
          {
            label: t('IntegrationsPage.bulk.delete.label'),
            icon: Trash2,
            variant: 'destructive',
            onClick: () => handleBulkDelete(),
          },
        ]}
      />

      {/* Setup wizard */}
      <SetupWizard
        isOpen={showWizard}
        onClose={() => setShowWizard(false)}
        onCreated={() => queryClient.invalidateQueries({ queryKey: ['integrations'] })}
      />

      {/* Start-from-template picker */}
      <TemplatePickerDialog
        isOpen={showTemplates}
        onClose={() => setShowTemplates(false)}
        onApplied={() => queryClient.invalidateQueries({ queryKey: ['integrations'] })}
      />

      {/* Delivery history + DLQ modal */}
      <DeliveryHistoryModal
        integrationId={deliveryModal?.integrationId ?? null}
        webhookId={deliveryModal?.webhookId ?? null}
        onClose={() => setDeliveryModal(null)}
      />
    </div>
  );
}
