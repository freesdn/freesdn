// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Automation Rules Page
 * 
 * Manage automation rules with CRUD operations and execution history.
 */
import React, { useCallback, useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { z } from 'zod';
import { PageHeader } from '@/components/layout';
import { CapabilityMaturityBadge } from '@/components/ui/capability-maturity-badge';
import { Skeleton } from '@/components/ui/skeleton';
import { StatusBadge, type StatusVariant } from '@/components/ui/status-indicator';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { FormDialog } from '@/components/ui/form-dialog';
import { FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { automationApi, AutomationRule, AutomationExecution, getApiErrorMessage } from '@/lib/api';
import { Zap, Plus, History } from 'lucide-react';
import { EmptyState } from '@/components/ui/empty-state';
import { useToast } from '@/hooks/use-toast';

// --------------- Trigger / Action type metadata ---------------
// `labelKey` is a suffix translated at the render site via
// t(`AutomationPage.triggerTypes.${value}`) / t(`AutomationPage.actionTypes.${labelKey}`).
const TRIGGER_TYPES = [
  { value: 'event', labelKey: 'event' },
  { value: 'schedule', labelKey: 'schedule' },
  { value: 'threshold', labelKey: 'threshold' },
  { value: 'manual', labelKey: 'manual' },
  { value: 'webhook', labelKey: 'webhook' },
] as const;

const ACTION_TYPE_OPTIONS = [
  { value: 'device.reboot', labelKey: 'deviceReboot' },
  { value: 'device.poe_cycle', labelKey: 'devicePoeCycle' },
  { value: 'device.locate', labelKey: 'deviceLocate' },
  { value: 'device.config', labelKey: 'deviceConfig' },
  { value: 'network.block_client', labelKey: 'networkBlockClient' },
  { value: 'network.unblock_client', labelKey: 'networkUnblockClient' },
  { value: 'network.quarantine', labelKey: 'networkQuarantine' },
  { value: 'alert.create', labelKey: 'alertCreate' },
  { value: 'alert.resolve', labelKey: 'alertResolve' },
  { value: 'notify.email', labelKey: 'notifyEmail' },
  { value: 'notify.webhook', labelKey: 'notifyWebhook' },
  { value: 'notify.slack', labelKey: 'notifySlack' },
  { value: 'notify.in_app', labelKey: 'notifyInApp' },
  { value: 'script.run', labelKey: 'scriptRun' },
  { value: 'api.call', labelKey: 'apiCall' },
] as const;

// Trigger type icons
const triggerIcons: Record<string, React.ReactNode> = {
  event: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
    </svg>
  ),
  schedule: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  ),
  threshold: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
    </svg>
  ),
  manual: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 15l-2 5L9 9l11 4-5 2zm0 0l5 5M7.188 2.239l.777 2.897M5.136 7.965l-2.898-.777M13.95 4.05l-2.122 2.122m-5.657 5.656l-2.12 2.122" />
    </svg>
  ),
};

interface RuleCardProps {
  rule: AutomationRule;
  onToggle: (id: string, enabled: boolean) => void;
  onDelete: (id: string) => void;
  onTrigger: (id: string) => void;
  onEdit: (rule: AutomationRule) => void;
}

// Helper to check if rule is enabled
const isRuleEnabled = (rule: AutomationRule) => rule.status === 'active';

const RuleCard: React.FC<RuleCardProps> = ({ rule, onToggle, onDelete, onTrigger, onEdit }) => {
  const { t } = useTranslation('automation');
  const [showActions, setShowActions] = useState(false);
  const enabled = isRuleEnabled(rule);

  return (
    <div className="bg-card rounded-xl shadow-sm border border-border p-6 hover:shadow-md transition-shadow">
      <div className="flex items-start justify-between">
        <div className="flex items-center space-x-3">
          <div className={`p-2 rounded-lg ${enabled ? 'bg-primary/10 text-primary' : 'bg-muted text-muted-foreground'}`}>
            {triggerIcons[rule.trigger_type] || triggerIcons.manual}
          </div>
          <div>
            <h3 className="font-semibold text-foreground">{rule.name}</h3>
            <p className="text-sm text-muted-foreground">{rule.description || t('AutomationPage.ruleCard.noDescription')}</p>
          </div>
        </div>
        
        <div className="relative">
          <button
            onClick={() => setShowActions(!showActions)}
            className="p-2 text-muted-foreground hover:text-foreground rounded-lg hover:bg-muted"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 5v.01M12 12v.01M12 19v.01M12 6a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2zm0 7a1 1 0 110-2 1 1 0 010 2z" />
            </svg>
          </button>
          
          {showActions && (
            <div className="absolute right-0 mt-2 w-48 bg-popover rounded-lg shadow-lg border border-border py-1 z-10">
              <button
                onClick={() => { onEdit(rule); setShowActions(false); }}
                className="w-full flex items-center px-4 py-2 text-sm text-popover-foreground hover:bg-muted"
              >
                <svg className="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                </svg>
                {t('AutomationPage.ruleCard.actions.edit')}
              </button>
              <button
                onClick={() => { onTrigger(rule.id); setShowActions(false); }}
                className="w-full flex items-center px-4 py-2 text-sm text-popover-foreground hover:bg-muted"
              >
                <svg className="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                {t('AutomationPage.ruleCard.actions.runNow')}
              </button>
              <button
                onClick={() => { onDelete(rule.id); setShowActions(false); }}
                className="w-full flex items-center px-4 py-2 text-sm text-destructive hover:bg-destructive/10"
              >
                <svg className="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
                {t('AutomationPage.ruleCard.actions.delete')}
              </button>
            </div>
          )}
        </div>
      </div>

      <div className="mt-4 flex items-center space-x-6 text-sm">
        <div className="flex items-center text-muted-foreground">
          <span className="capitalize">{t(`AutomationPage.triggerTypes.${rule.trigger_type}`, { defaultValue: rule.trigger_type })}</span>
        </div>
        <div className="flex items-center text-muted-foreground">
          <span>{t('AutomationPage.ruleCard.actionsCount', { n: rule.actions?.length || 0 })}</span>
        </div>
        <div className="flex items-center text-muted-foreground">
          <span>{t('AutomationPage.ruleCard.executionsCount', { n: rule.trigger_count || 0 })}</span>
        </div>
        {rule.last_triggered && (
          <div className="flex items-center text-muted-foreground">
            <span>{t('AutomationPage.ruleCard.lastTriggered', { date: new Date(rule.last_triggered).toLocaleDateString() })}</span>
          </div>
        )}
      </div>

      <div className="mt-4 flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <span className="text-sm text-muted-foreground">{t('AutomationPage.ruleCard.priority', { value: rule.priority })}</span>
          {rule.cooldown_seconds > 0 && (
            <span className="text-sm text-muted-foreground">{t('AutomationPage.ruleCard.cooldown', { value: rule.cooldown_seconds })}</span>
          )}
          <StatusBadge
            variant={
              rule.status === 'active' ? 'success' :
              rule.status === 'paused' ? 'warning' :
              rule.status === 'error' ? 'error' :
              'neutral'
            }
            hideIcon
            size="sm"
            className="ml-2"
          >
            {t(`AutomationPage.status.${rule.status}`, { defaultValue: rule.status })}
          </StatusBadge>
        </div>
        
        <label className="relative inline-flex items-center cursor-pointer">
          <input
            type="checkbox"
            className="sr-only peer"
            checked={enabled}
            onChange={(e) => onToggle(rule.id, e.target.checked)}
          />
          <div className="w-11 h-6 bg-muted peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary/30 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-background after:border-border after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary"></div>
        </label>
      </div>
    </div>
  );
};

interface ExecutionRowProps {
  execution: AutomationExecution;
}

const ExecutionRow: React.FC<ExecutionRowProps> = ({ execution }) => {
  const { t } = useTranslation('automation');
  const actionsCount = Array.isArray(execution.actions_executed) ? execution.actions_executed.length : 0;
  // Backend returns ``success: bool`` + ``triggered_at`` + ``error``.
  // Previous code read non-existent ``status`` / ``started_at`` /
  // ``error_message`` → rows rendered as "neutral / Invalid Date".
  const successVariant: StatusVariant = execution.success ? 'success' : 'error';
  const successLabel = execution.success
    ? t('AutomationPage.executionRow.success')
    : t('AutomationPage.executionRow.failed');

  return (
    <tr className="hover:bg-muted/50">
      <td className="px-6 py-4 whitespace-nowrap">
        <span className="text-sm font-medium text-foreground">{execution.rule_id.slice(0, 8)}...</span>
      </td>
      <td className="px-6 py-4 whitespace-nowrap">
        <StatusBadge variant={successVariant} hideIcon size="sm">
          {successLabel}
        </StatusBadge>
      </td>
      <td className="px-6 py-4 whitespace-nowrap text-sm text-muted-foreground">
        {t('AutomationPage.executionRow.actionsCount', { n: actionsCount })}
      </td>
      <td className="px-6 py-4 whitespace-nowrap text-sm text-muted-foreground">
        {execution.duration_ms ? `${execution.duration_ms}ms` : '-'}
      </td>
      <td className="px-6 py-4 whitespace-nowrap text-sm text-muted-foreground">
        {new Date(execution.triggered_at).toLocaleString()}
      </td>
      <td className="px-6 py-4 whitespace-nowrap text-sm text-muted-foreground">
        {execution.error ? (
          <span className="text-destructive truncate max-w-xs block" title={execution.error}>
            {execution.error}
          </span>
        ) : (
          '-'
        )}
      </td>
    </tr>
  );
};

// --------------- Create Rule Modal ---------------

const createRuleSchema = z.object({
  name: z.string().min(1, 'Rule name is required'),
  description: z.string(),
  trigger_type: z.string().min(1),
  action_type: z.string().min(1),
  priority: z.coerce.number().int().min(0).max(1000),
  cooldown_seconds: z.coerce.number().int().min(0),
});
type CreateRuleFormValues = z.infer<typeof createRuleSchema>;

const createRuleDefaults: CreateRuleFormValues = {
  name: '',
  description: '',
  trigger_type: 'event',
  action_type: 'notify.in_app',
  priority: 0,
  cooldown_seconds: 60,
};

interface RuleFormModalProps {
  isOpen: boolean;
  onClose: () => void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onSubmit: (data: any) => Promise<void>;
  /** When set, the dialog runs in edit mode and prefills from this rule. */
  rule?: AutomationRule | null;
}

// Unified create/edit dialog. ``FormDialog`` re-seeds ``defaultValues`` every
// time it opens, so switching ``rule`` reliably prefills the edit form.
const RuleFormModal: React.FC<RuleFormModalProps> = ({ isOpen, onClose, onSubmit, rule }) => {
  const { t } = useTranslation('automation');
  const isEdit = !!rule;
  const defaultValues: CreateRuleFormValues = rule
    ? {
        name: rule.name,
        description: rule.description || '',
        trigger_type: rule.trigger_type,
        action_type: rule.actions?.[0]?.action_type || 'notify.in_app',
        priority: rule.priority,
        cooldown_seconds: rule.cooldown_seconds,
      }
    : createRuleDefaults;

  return (
    <FormDialog<CreateRuleFormValues>
      open={isOpen}
      onOpenChange={(next) => { if (!next) onClose(); }}
      title={isEdit ? t('AutomationPage.ruleCard.actions.edit') : t('AutomationPage.createModal.title')}
      schema={createRuleSchema}
      defaultValues={defaultValues}
      submitLabel={isEdit ? t('common:save') : t('AutomationPage.createModal.submitLabel')}
      contentClassName="sm:max-w-lg"
      onSubmit={async (values) => {
        if (isEdit && rule) {
          // Preserve existing action params; only swap the first action's
          // type (the form models a single action). Trigger_config is left
          // untouched, the create modal can't author it, so editing here
          // must not clobber what's already stored.
          const existingActions = rule.actions && rule.actions.length > 0 ? rule.actions : [];
          const nextActions = existingActions.length > 0
            ? [{ ...existingActions[0], action_type: values.action_type }, ...existingActions.slice(1)]
            : [{ action_type: values.action_type, params: {} }];
          await onSubmit({
            name: values.name,
            description: values.description || undefined,
            trigger_type: values.trigger_type,
            actions: nextActions,
            priority: values.priority,
            cooldown_seconds: values.cooldown_seconds,
          });
          return;
        }
        await onSubmit({
          name: values.name,
          description: values.description || undefined,
          trigger_type: values.trigger_type,
          trigger_config: {},
          actions: [{ action_type: values.action_type, params: {} }],
          priority: values.priority,
          cooldown_seconds: values.cooldown_seconds,
          max_triggers_per_hour: 100,
        });
      }}
    >
      {(form) => (
        <>
          <FormField
            control={form.control}
            name="name"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AutomationPage.createModal.fields.name.label')}</FormLabel>
                <FormControl>
                  <Input placeholder={t('AutomationPage.createModal.fields.name.placeholder')} {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="description"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AutomationPage.createModal.fields.description.label')}</FormLabel>
                <FormControl>
                  <Textarea
                    rows={2}
                    placeholder={t('AutomationPage.createModal.fields.description.placeholder')}
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="trigger_type"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AutomationPage.createModal.fields.triggerType.label')}</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {TRIGGER_TYPES.map((opt) => (
                      <SelectItem key={opt.value} value={opt.value}>{t(`AutomationPage.triggerTypes.${opt.labelKey}`)}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="action_type"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('AutomationPage.createModal.fields.action.label')}</FormLabel>
                <Select value={field.value} onValueChange={field.onChange}>
                  <FormControl>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    {ACTION_TYPE_OPTIONS.map((a) => (
                      <SelectItem key={a.value} value={a.value}>{t(`AutomationPage.actionTypes.${a.labelKey}`)}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
          <div className="grid grid-cols-2 gap-4">
            <FormField
              control={form.control}
              name="priority"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('AutomationPage.createModal.fields.priority.label')}</FormLabel>
                  <FormControl>
                    <Input type="number" min={0} max={1000} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="cooldown_seconds"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('AutomationPage.createModal.fields.cooldown.label')}</FormLabel>
                  <FormControl>
                    <Input type="number" min={0} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>
        </>
      )}
    </FormDialog>
  );
};

// --------------- Main Page ---------------
const AUTOMATION_TABS = ['rules', 'history'] as const;

export default function AutomationPage() {
  const { t } = useTranslation('automation');
  const { toast } = useToast();
  const navigate = useNavigate();
  const { tab: urlTab } = useParams<{ tab?: string }>();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const activeTab = AUTOMATION_TABS.includes(urlTab as any) ? (urlTab as 'rules' | 'history') : 'rules';
  const setActiveTab = (v: string) => navigate(v === 'rules' ? '/automation' : `/automation/${v}`, { replace: true });
  const [rules, setRules] = useState<AutomationRule[]>([]);
  const [executions, setExecutions] = useState<AutomationExecution[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterType, setFilterType] = useState<string>('');
  const [filterEnabled, setFilterEnabled] = useState<string>('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [editingRule, setEditingRule] = useState<AutomationRule | null>(null);

  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const params: Record<string, string> = {};
      if (filterType) params.trigger_type = filterType;
      if (filterEnabled) {
        // Map enabled filter to status filter
        params.status = filterEnabled === 'true' ? 'active' : 'disabled';
      }

      const [rulesRes, executionsRes] = await Promise.all([
        automationApi.listRules(params),
        automationApi.listExecutions({ per_page: 20 }),
      ]);

      setRules(rulesRes.data.items || []);
      setExecutions(executionsRes.data.items || []);
    } catch (err: unknown) {
      console.error('Failed to load automation data:', err);
      setError(getApiErrorMessage(err, t('AutomationPage.errors.loadFailed')));
    } finally {
      setLoading(false);
    }
  }, [filterType, filterEnabled, t]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleToggle = async (id: string, enabled: boolean) => {
    try {
      if (enabled) {
        await automationApi.enableRule(id);
      } else {
        await automationApi.disableRule(id);
      }
      // Refresh to get updated status
      loadData();
    } catch (err: unknown) {
      toast({ title: t('AutomationPage.toast.errorTitle'), description: t('AutomationPage.toast.updateFailed', { error: getApiErrorMessage(err) }), variant: "destructive" });
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm(t('AutomationPage.confirm.delete'))) return;

    try {
      await automationApi.deleteRule(id);
      setRules(rules.filter(r => r.id !== id));
    } catch (err: unknown) {
      toast({ title: t('AutomationPage.toast.errorTitle'), description: t('AutomationPage.toast.deleteFailed', { error: getApiErrorMessage(err) }), variant: "destructive" });
    }
  };

  const handleTrigger = async (id: string) => {
    try {
      await automationApi.triggerRule(id);
      toast({ title: t('AutomationPage.toast.successTitle'), description: t('AutomationPage.toast.triggered') });
      loadData(); // Refresh to show new execution
    } catch (err: unknown) {
      toast({ title: t('AutomationPage.toast.errorTitle'), description: t('AutomationPage.toast.triggerFailed', { error: getApiErrorMessage(err) }), variant: "destructive" });
    }
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleCreate = async (data: any) => {
    // Errors propagate to FormDialog's banner; success closes the dialog.
    await automationApi.createRule(data);
    setShowCreateModal(false);
    loadData();
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const handleUpdate = async (data: any) => {
    if (!editingRule) return;
    // Errors propagate to FormDialog's banner; success closes the dialog.
    await automationApi.updateRule(editingRule.id, data);
    setEditingRule(null);
    loadData();
  };

  if (loading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-10 w-1/3" />
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Skeleton className="h-48 w-full rounded-xl" />
          <Skeleton className="h-48 w-full rounded-xl" />
          <Skeleton className="h-48 w-full rounded-xl" />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
        {/* Header */}
        <PageHeader
          title={t('AutomationPage.header.title')}
          titleBadge={<CapabilityMaturityBadge capabilityId="automation" />}
          description={t('AutomationPage.header.description')}
          icon={Zap}
          primaryAction={{
            label: t('AutomationPage.header.createRule'),
            icon: Plus,
            onClick: () => setShowCreateModal(true)
          }}
        />

        {/* Error Alert */}
        {error && (
          <div className="bg-destructive/10 border border-destructive/20 rounded-lg p-4">
            <span className="text-destructive">{error}</span>
          </div>
        )}

        {/* Tabs */}
        <div className="border-b border-border">
          <nav className="-mb-px flex space-x-8">
            <button
              onClick={() => setActiveTab('rules')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'rules'
                  ? 'border-primary text-primary'
                  : 'border-transparent text-muted-foreground hover:text-foreground hover:border-border'
              }`}
            >
              {t('AutomationPage.tabs.rules', { n: rules.length })}
            </button>
            <button
              onClick={() => setActiveTab('history')}
              className={`py-4 px-1 border-b-2 font-medium text-sm ${
                activeTab === 'history'
                  ? 'border-primary text-primary'
                  : 'border-transparent text-muted-foreground hover:text-foreground hover:border-border'
              }`}
            >
              {t('AutomationPage.tabs.history')}
            </button>
          </nav>
        </div>

        {/* Rules Tab */}
        {activeTab === 'rules' && (
          <>
            {/* Filters */}
            <div className="flex items-center space-x-4">
              <select
                value={filterType}
                onChange={(e) => setFilterType(e.target.value)}
                className="border border-border rounded-lg px-3 py-2 text-sm bg-background text-foreground"
              >
                <option value="">{t('AutomationPage.filters.allTriggers')}</option>
                <option value="event">{t('AutomationPage.triggerTypes.event')}</option>
                <option value="schedule">{t('AutomationPage.triggerTypes.schedule')}</option>
                <option value="threshold">{t('AutomationPage.triggerTypes.threshold')}</option>
                <option value="manual">{t('AutomationPage.triggerTypes.manual')}</option>
              </select>
              <select
                value={filterEnabled}
                onChange={(e) => setFilterEnabled(e.target.value)}
                className="border border-border rounded-lg px-3 py-2 text-sm bg-background text-foreground"
              >
                <option value="">{t('AutomationPage.filters.allStatus')}</option>
                <option value="true">{t('AutomationPage.filters.enabled')}</option>
                <option value="false">{t('AutomationPage.filters.disabled')}</option>
              </select>
              <button
                onClick={loadData}
                className="px-3 py-2 border border-border rounded-lg text-sm hover:bg-muted text-foreground"
              >
                {t('AutomationPage.filters.refresh')}
              </button>
            </div>

            {/* Rules Grid */}
            {rules.length === 0 ? (
              <EmptyState
                icon={Zap}
                title={t('AutomationPage.empty.rules.title')}
                description={t('AutomationPage.empty.rules.description')}
                action={{ label: t('AutomationPage.empty.rules.action'), onClick: () => setShowCreateModal(true), icon: Plus }}
                variant="card"
              />
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {rules.map((rule) => (
                  <RuleCard
                    key={rule.id}
                    rule={rule}
                    onToggle={handleToggle}
                    onDelete={handleDelete}
                    onTrigger={handleTrigger}
                    onEdit={setEditingRule}
                  />
                ))}
              </div>
            )}
          </>
        )}

        {/* History Tab */}
        {activeTab === 'history' && (
          <div className="bg-card rounded-xl shadow-sm border border-border overflow-hidden">
            {executions.length === 0 ? (
              <EmptyState
                icon={History}
                title={t('AutomationPage.empty.history.title')}
                description={t('AutomationPage.empty.history.description')}
                variant="card"
              />
            ) : (
              <table className="min-w-full divide-y divide-border">
                <thead className="bg-muted">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      {t('AutomationPage.historyTable.rule')}
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      {t('AutomationPage.historyTable.status')}
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      {t('AutomationPage.historyTable.actions')}
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      {t('AutomationPage.historyTable.duration')}
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      {t('AutomationPage.historyTable.time')}
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                      {t('AutomationPage.historyTable.error')}
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-card divide-y divide-border">
                  {executions.map((execution) => (
                    <ExecutionRow key={execution.id} execution={execution} />
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {/* Create Rule Modal */}
        <RuleFormModal
          isOpen={showCreateModal}
          onClose={() => setShowCreateModal(false)}
          onSubmit={handleCreate}
        />

        {/* Edit Rule Modal, prefilled from the selected rule, submits via updateRule */}
        <RuleFormModal
          isOpen={!!editingRule}
          onClose={() => setEditingRule(null)}
          onSubmit={handleUpdate}
          rule={editingRule}
        />
      </div>
  );
}

