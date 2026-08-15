// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - AI Settings Page
 *
 * Configure LLM providers (OpenAI, Anthropic, Ollama) with API keys,
 * base URLs, default models, and connectivity testing.
 */

import { useState, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Brain,
  Key,
  CheckCircle,
  XCircle,
  Loader2,
  ExternalLink,
  AlertCircle,
} from 'lucide-react';

import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { cn } from '@/lib/utils';
import { PageHeader } from '@/components/layout';


// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface ProviderConfig {
  provider: string;
  is_enabled: boolean;
  default_model: string | null;
  base_url: string | null;
  api_key_set: boolean;
  settings: Record<string, unknown>;
  llm_org_policy: string;
  monthly_token_budget: number;
  tokens_used_this_month: number;
}

interface GovernanceUsage {
  llm_org_policy: string;
  monthly_token_budget: number;
  tokens_used_this_month: number;
  percentage_used: number;
  budget_remaining: number;
}

interface LLMCallLogEntry {
  id: string;
  provider: string;
  model: string;
  operation: string;
  input_fields_sent: string[];
  prompt_tokens: number;
  completion_tokens: number;
  success: boolean;
  error: string | null;
  latency_ms: number;
  rule_id: string | null;
  created_at: string;
}

interface TestResult {
  success: boolean;
  error?: string;
}

const PROVIDER_META: Record<string, {
  label: string;
  descriptionKey: string;
  models: string[];
  needsApiKey: boolean;
  needsBaseUrl: boolean;
  docsUrl: string;
}> = {
  openai: {
    label: 'OpenAI',
    descriptionKey: 'providers.openai.description',
    models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-3.5-turbo'],
    needsApiKey: true,
    needsBaseUrl: false,
    docsUrl: 'https://platform.openai.com/api-keys',
  },
  anthropic: {
    label: 'Anthropic',
    descriptionKey: 'providers.anthropic.description',
    models: ['claude-sonnet-4-20250514', 'claude-haiku-4-5-20251001', 'claude-opus-4-5'],
    needsApiKey: true,
    needsBaseUrl: false,
    docsUrl: 'https://console.anthropic.com/settings/keys',
  },
  ollama: {
    label: 'Ollama',
    descriptionKey: 'providers.ollama.description',
    models: ['llama3.2', 'llama3.1', 'mistral', 'qwen2.5', 'deepseek-r1'],
    needsApiKey: false,
    needsBaseUrl: true,
    docsUrl: 'https://ollama.ai',
  },
};


// ─────────────────────────────────────────────────────────────────────────────
// Provider card
// ─────────────────────────────────────────────────────────────────────────────

// Fallback metadata for providers the backend may return that aren't in
// PROVIDER_META (e.g. a newly added provider). Without this, an unknown
// `config.provider` yields `meta === undefined` and every `meta.*` access
// below white-screens the whole AI settings tab.
const DEFAULT_PROVIDER_META: (typeof PROVIDER_META)[string] = {
  label: '',
  descriptionKey: '',
  models: [],
  needsApiKey: true,
  needsBaseUrl: false,
  docsUrl: '#',
};

function ProviderCard({ config }: { config: ProviderConfig }) {
  const { t } = useTranslation('settings');
  const queryClient = useQueryClient();
  const meta = PROVIDER_META[config.provider] ?? {
    ...DEFAULT_PROVIDER_META,
    label: config.provider,
  };

  const [apiKey, setApiKey] = useState('');
  const [baseUrl, setBaseUrl] = useState(config.base_url ?? 'http://localhost:11434');
  const [defaultModel, setDefaultModel] = useState(config.default_model ?? '');
  const [isEnabled, setIsEnabled] = useState(config.is_enabled);
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [testLoading, setTestLoading] = useState(false);

  // Sync local state when server data changes (e.g. after mutation invalidation)
  useEffect(() => {
    setIsEnabled(config.is_enabled);
    setBaseUrl(config.base_url ?? 'http://localhost:11434');
    setDefaultModel(config.default_model ?? '');
  }, [config.is_enabled, config.base_url, config.default_model]);

  const updateMutation = useMutation({
    mutationFn: (data: Partial<{
      api_key: string;
      base_url: string;
      default_model: string;
      is_enabled: boolean;
    }>) =>
      api.put(`/ai/providers/${config.provider}`, data).then((r) => r.data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ai-providers'] });
    },
    onError: () => {
      // Roll back optimistic toggle state on failure
      setIsEnabled(config.is_enabled);
    },
  });

  const handleSave = () => {
    const data: Record<string, unknown> = {
      is_enabled: isEnabled,
      default_model: defaultModel || undefined,
    };
    if (meta.needsApiKey && apiKey) data.api_key = apiKey;
    if (meta.needsBaseUrl) data.base_url = baseUrl;
    updateMutation.mutate(data as Parameters<typeof updateMutation.mutate>[0]);
  };

  const handleToggle = (enabled: boolean) => {
    setIsEnabled(enabled);
    updateMutation.mutate({ is_enabled: enabled });
  };

  const handleTest = async () => {
    setTestLoading(true);
    setTestResult(null);
    try {
      const res = await api.post(`/ai/providers/${config.provider}/test`);
      setTestResult(res.data);
    } catch {
      setTestResult({ success: false, error: t('AISettingsPage.test.requestFailed') });
    } finally {
      setTestLoading(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              {meta.label}
              {config.is_enabled ? (
                <Badge className="bg-success/10 text-success border-success/20" variant="outline">
                  {t('AISettingsPage.status.enabled')}
                </Badge>
              ) : (
                <Badge variant="secondary">{t('AISettingsPage.status.disabled')}</Badge>
              )}
              {config.api_key_set && (
                <Badge variant="outline" className="text-xs">
                  <Key className="mr-1 h-3 w-3" />
                  {t('AISettingsPage.status.keySet')}
                </Badge>
              )}
            </CardTitle>
            <CardDescription className="mt-1">{t(`AISettingsPage.${meta.descriptionKey}`)}</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Switch
              checked={isEnabled}
              onCheckedChange={handleToggle}
              disabled={updateMutation.isPending}
            />
            <a
              href={meta.docsUrl}
              target="_blank"
              rel="noreferrer"
              className="text-muted-foreground hover:text-foreground"
            >
              <ExternalLink className="h-4 w-4" />
            </a>
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* API Key input */}
        {meta.needsApiKey && (
          <div className="space-y-1.5">
            <Label htmlFor={`${config.provider}-key`}>{t('AISettingsPage.fields.apiKey')}</Label>
            <Input
              id={`${config.provider}-key`}
              type="password"
              placeholder={config.api_key_set ? '••••••••••••••••' : t('AISettingsPage.fields.apiKeyPlaceholder')}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
            />
            {config.api_key_set && !apiKey && (
              <p className="text-xs text-muted-foreground">
                {t('AISettingsPage.fields.apiKeyHint')}
              </p>
            )}
          </div>
        )}

        {/* Base URL for Ollama */}
        {meta.needsBaseUrl && (
          <div className="space-y-1.5">
            <Label htmlFor={`${config.provider}-url`}>{t('AISettingsPage.fields.baseUrl')}</Label>
            <Input
              id={`${config.provider}-url`}
              type="url"
              placeholder="http://localhost:11434"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
            />
          </div>
        )}

        {/* Default model */}
        <div className="space-y-1.5">
          <Label htmlFor={`${config.provider}-model`}>{t('AISettingsPage.fields.defaultModel')}</Label>
          <Select value={defaultModel} onValueChange={setDefaultModel}>
            <SelectTrigger id={`${config.provider}-model`}>
              <SelectValue placeholder={t('AISettingsPage.fields.defaultModelPlaceholder')} />
            </SelectTrigger>
            <SelectContent>
              {meta.models.map((m) => (
                <SelectItem key={m} value={m}>
                  {m}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {/* Test result */}
        {testResult && (
          <Alert
            className={
              testResult.success
                ? 'border-green-200 bg-green-50 dark:border-green-800 dark:bg-green-950/30'
                : 'border-red-200 bg-red-50 dark:border-red-800 dark:bg-red-950/30'
            }
          >
            {testResult.success ? (
              <CheckCircle className="h-4 w-4 text-green-600" />
            ) : (
              <XCircle className="h-4 w-4 text-red-600" />
            )}
            <AlertDescription className={testResult.success ? 'text-green-700 dark:text-green-300' : 'text-red-700 dark:text-red-300'}>
              {testResult.success
                ? t('AISettingsPage.test.success')
                : testResult.error ?? t('AISettingsPage.test.failed')}
            </AlertDescription>
          </Alert>
        )}

        {updateMutation.isError && (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{t('AISettingsPage.errors.saveFailed')}</AlertDescription>
          </Alert>
        )}

        {/* Actions */}
        <div className="flex gap-2 pt-1">
          <Button
            onClick={handleSave}
            disabled={updateMutation.isPending}
            size="sm"
          >
            {updateMutation.isPending && (
              <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />
            )}
            {t('AISettingsPage.actions.save')}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleTest}
            disabled={testLoading || (meta.needsApiKey && !config.api_key_set)}
            title={meta.needsApiKey && !config.api_key_set ? t('AISettingsPage.actions.configureApiKeyFirst') : undefined}
          >
            {testLoading ? (
              <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />
            ) : testResult?.success ? (
              <CheckCircle className="mr-2 h-3.5 w-3.5 text-green-600" />
            ) : (
              <></>
            )}
            {t('AISettingsPage.actions.testConnection')}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}


// ─────────────────────────────────────────────────────────────────────────────
// Governance Panel
// ─────────────────────────────────────────────────────────────────────────────

const POLICY_OPTIONS = [
  { value: 'disabled', labelKey: 'policy.disabled.label', descriptionKey: 'policy.disabled.description' },
  { value: 'local_only', labelKey: 'policy.localOnly.label', descriptionKey: 'policy.localOnly.description' },
  { value: 'cloud_approved', labelKey: 'policy.cloudApproved.label', descriptionKey: 'policy.cloudApproved.description' },
];

function formatLatency(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
}

function GovernancePanel() {
  const { t } = useTranslation('settings');
  const queryClient = useQueryClient();

  const { data: providers } = useQuery<ProviderConfig[]>({
    queryKey: ['ai-providers'],
    queryFn: () => api.get('/ai/providers').then((r) => r.data),
  });

  const { data: usage, isLoading, isError } = useQuery<GovernanceUsage>({
    queryKey: ['ai-governance-usage'],
    queryFn: () => api.get('/ai/governance/usage').then((r) => r.data),
  });

  const [logPage, setLogPage] = useState(0);
  const logsPageSize = 20;

  const { data: logsData } = useQuery<{ logs: LLMCallLogEntry[]; total: number }>({
    queryKey: ['ai-governance-logs', logPage],
    queryFn: () =>
      api.get(`/ai/governance/logs?size=${logsPageSize}&page=${logPage + 1}`).then((r) => r.data),
  });

  // Use the first available provider for governance updates (policy is org-wide)
  const targetProvider = providers?.[0]?.provider;

  const [policyError, setPolicyError] = useState<string | null>(null);

  const policyMutation = useMutation({
    mutationFn: (data: { llm_org_policy?: string; monthly_token_budget?: number }) => {
      if (!targetProvider) return Promise.reject(new Error('No provider configured'));
      return api.put(`/ai/providers/${targetProvider}`, data).then((r) => r.data);
    },
    onSuccess: () => {
      setPolicyError(null);
      queryClient.invalidateQueries({ queryKey: ['ai-governance-usage'] });
      queryClient.invalidateQueries({ queryKey: ['ai-providers'] });
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      setPolicyError(err?.response?.data?.detail || t('AISettingsPage.errors.governanceUpdateFailed'));
    },
  });

  const [budget, setBudget] = useState<string>('100000');

  // Sync budget state when server data arrives
  useEffect(() => {
    if (usage?.monthly_token_budget !== undefined) {
      setBudget(String(usage.monthly_token_budget));
    }
  }, [usage?.monthly_token_budget]);

  const handleBudgetUpdate = () => {
    const parsed = parseInt(budget);
    const safeBudget = Number.isFinite(parsed) && parsed > 0 ? parsed : 100000;
    setBudget(String(safeBudget));
    policyMutation.mutate({ monthly_token_budget: safeBudget });
  };

  const percentage = usage?.percentage_used ?? 0;
  const barColor =
    percentage >= 80 ? 'bg-red-500' : percentage >= 50 ? 'bg-yellow-500' : 'bg-green-500';

  if (isLoading) return null;
  if (isError) {
    return (
      <Alert>
        <AlertCircle className="h-4 w-4" />
        <AlertDescription>{t('AISettingsPage.errors.governanceLoadFailed')}</AlertDescription>
      </Alert>
    );
  }

  return (
    <div className="space-y-4">
      {/* Policy selector */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">{t('AISettingsPage.governance.title')}</CardTitle>
          <CardDescription>
            {t('AISettingsPage.governance.description')}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {!targetProvider && (
            <Alert>
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>
                {t('AISettingsPage.governance.noProviderHint')}
              </AlertDescription>
            </Alert>
          )}
          {policyError && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{policyError}</AlertDescription>
            </Alert>
          )}
          <div className="space-y-1.5">
            <Label>{t('AISettingsPage.governance.orgPolicy')}</Label>
            <Select
              value={usage?.llm_org_policy ?? 'disabled'}
              onValueChange={(v) => policyMutation.mutate({ llm_org_policy: v })}
              disabled={!targetProvider || policyMutation.isPending}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {POLICY_OPTIONS.map((opt) => (
                  <SelectItem key={opt.value} value={opt.value}>
                    <span className="font-medium">{t(`AISettingsPage.${opt.labelKey}`)}</span>
                    <span className="ml-2 text-xs text-muted-foreground">{t(`AISettingsPage.${opt.descriptionKey}`)}</span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Token budget */}
          <div className="space-y-1.5">
            <Label>{t('AISettingsPage.governance.monthlyBudget')}</Label>
            <div className="flex gap-2">
              <Input
                type="number"
                value={budget}
                onChange={(e) => setBudget(e.target.value)}
                className="w-40"
                min={1}
              />
              <Button
                size="sm"
                variant="outline"
                onClick={handleBudgetUpdate}
                disabled={!targetProvider || policyMutation.isPending}
              >
                {t('AISettingsPage.actions.update')}
              </Button>
            </div>
          </div>

          {/* Usage bar */}
          {usage && (
            <div className="space-y-1.5">
              <div className="flex justify-between text-sm">
                <span>{t('AISettingsPage.governance.tokenUsage')}</span>
                <span className="font-mono">
                  {(usage.tokens_used_this_month ?? 0).toLocaleString()} / {(usage.monthly_token_budget ?? 0).toLocaleString()}
                </span>
              </div>
              <div className="h-2 rounded-full bg-muted">
                <div
                  className={cn('h-2 rounded-full transition-all', barColor)}
                  style={{ width: `${Math.min(100, percentage)}%` }}
                />
              </div>
              <p className="text-xs text-muted-foreground">
                {t('AISettingsPage.governance.usageSummary', {
                  percent: percentage.toFixed(1),
                  remaining: (usage.budget_remaining ?? 0).toLocaleString(),
                })}
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Call log */}
      {logsData && (logsData.logs?.length ?? 0) > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{t('AISettingsPage.callLog.title')}</CardTitle>
            <CardDescription>
              {t('AISettingsPage.callLog.description')}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="pb-2 pr-3">{t('AISettingsPage.callLog.columns.time')}</th>
                    <th className="pb-2 pr-3">{t('AISettingsPage.callLog.columns.operation')}</th>
                    <th className="pb-2 pr-3">{t('AISettingsPage.callLog.columns.provider')}</th>
                    <th className="pb-2 pr-3">{t('AISettingsPage.callLog.columns.tokens')}</th>
                    <th className="pb-2 pr-3">{t('AISettingsPage.callLog.columns.latency')}</th>
                    <th className="pb-2">{t('AISettingsPage.callLog.columns.status')}</th>
                  </tr>
                </thead>
                <tbody>
                  {logsData.logs.map((log) => (
                    <tr key={log.id} className="border-b last:border-0">
                      <td className="py-1.5 pr-3 text-xs text-muted-foreground">
                        {new Date(log.created_at).toLocaleString()}
                      </td>
                      <td className="py-1.5 pr-3">
                        <Badge variant="outline" className="text-xs">{log.operation}</Badge>
                      </td>
                      <td className="py-1.5 pr-3 text-xs">{log.provider}/{log.model}</td>
                      <td className="py-1.5 pr-3 font-mono text-xs">
                        {log.prompt_tokens + log.completion_tokens}
                      </td>
                      <td className="py-1.5 pr-3 font-mono text-xs">{formatLatency(log.latency_ms)}</td>
                      <td className="py-1.5">
                        {log.success ? (
                          <CheckCircle className="h-3.5 w-3.5 text-green-600" />
                        ) : (
                          <XCircle className="h-3.5 w-3.5 text-red-600" />
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {/* Pagination */}
            {logsData.total > logsPageSize && (
              <div className="flex items-center justify-between pt-3 border-t mt-3">
                <p className="text-xs text-muted-foreground">
                  {t('AISettingsPage.pagination.showing', {
                    from: logPage * logsPageSize + 1,
                    to: Math.min((logPage + 1) * logsPageSize, logsData.total),
                    total: logsData.total,
                  })}
                </p>
                <div className="flex gap-1">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setLogPage((p) => Math.max(0, p - 1))}
                    disabled={logPage === 0}
                  >
                    {t('AISettingsPage.pagination.previous')}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setLogPage((p) => p + 1)}
                    disabled={(logPage + 1) * logsPageSize >= logsData.total}
                  >
                    {t('AISettingsPage.pagination.next')}
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}


// ─────────────────────────────────────────────────────────────────────────────
// Main Page
// ─────────────────────────────────────────────────────────────────────────────

export default function AISettingsPage({ embedded }: { embedded?: boolean } = {}) {
  const { t } = useTranslation('settings');
  const { data: providers, isLoading, isError } = useQuery<ProviderConfig[]>({
    queryKey: ['ai-providers'],
    queryFn: () => api.get('/ai/providers').then((r) => r.data),
  });

  return (
    <div className="space-y-6">
      {!embedded && (
        <PageHeader
          icon={Brain}
          title={t('AISettingsPage.header.title')}
          description={t('AISettingsPage.header.subtitle')}
        />
      )}

      {isLoading && (
        <div className="grid gap-4 md:grid-cols-1 lg:grid-cols-1 xl:grid-cols-1 max-w-2xl">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-40 rounded-xl" />
          ))}
        </div>
      )}

      {isError && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>
            {t('AISettingsPage.errors.loadProvidersPrefix')}{' '}
            <code className="font-mono">ai.admin</code>{' '}
            {t('AISettingsPage.errors.loadProvidersSuffix')}
          </AlertDescription>
        </Alert>
      )}

      {providers && (
        <div className="grid gap-4 md:grid-cols-1 lg:grid-cols-1 xl:grid-cols-1 max-w-2xl">
          {providers.map((cfg) => (
            <ProviderCard key={cfg.provider} config={cfg} />
          ))}
        </div>
      )}

      {/* Governance panel */}
      <div className="max-w-2xl">
        <GovernancePanel />
      </div>

      {/* Info box */}
      <div className="max-w-2xl rounded-lg border bg-muted/30 p-4 text-sm text-muted-foreground">
        <p className="font-medium text-foreground">{t('AISettingsPage.info.title')}</p>
        <ul className="mt-2 list-disc space-y-1 pl-4">
          <li>{t('AISettingsPage.info.encryption')}</li>
          <li>{t('AISettingsPage.info.ollamaLocal')}</li>
          <li>{t('AISettingsPage.info.readAccess')}</li>
        </ul>
      </div>
    </div>
  );
}
