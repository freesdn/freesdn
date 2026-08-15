// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Add Hypervisor Dialog
 *
 * Built on the canonical FormDialog primitive.
 * Supports both API Token and Username/Password authentication.
 * The "Test Connection" button is non-form state (a side action) and lives
 * inside the children render-prop with its own local state.
 */

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { Loader2, Server, Eye, EyeOff, XCircle, CheckCircle, TestTube, Zap, Info } from 'lucide-react';
import { z } from 'zod';
import { FormDialog } from '@/components/ui/form-dialog';
import { FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { controllersApi, sitesApi } from '@/lib/api';

interface AddHypervisorDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface TestResult {
  success: boolean;
  message: string;
  error?: string;
  details?: {
    latency_ms?: number;
    controller_version?: string;
    controller_name?: string;
  };
}

// Realm option labels are translated at the render site via `labelKey`.
// `LDAP` and `Active Directory` stay as technical/product terms.
const PROXMOX_REALMS = [
  { value: 'pam', labelKey: 'pam' },
  { value: 'pve', labelKey: 'pve' },
  { value: 'ldap', labelKey: 'ldap' },
  { value: 'ad', labelKey: 'ad' },
];

const buildSchema = (t: TFunction) =>
  z
    .object({
      name: z.string().min(1, t('AddHypervisorDialog.validation.nameRequired')),
      site_id: z.string().min(1, t('AddHypervisorDialog.validation.siteRequired')),
      host: z.string().min(1, t('AddHypervisorDialog.validation.hostRequired')),
      port: z.coerce.number().int().min(1).max(65535),
      use_ssl: z.boolean(),
      verify_ssl: z.boolean(),
      sync_enabled: z.boolean(),
      sync_interval_seconds: z.coerce.number().int().positive(),
      auth_mode: z.enum(['token', 'password']),
      token_id: z.string(),
      token_secret: z.string(),
      username: z.string(),
      password: z.string(),
      realm: z.string(),
    })
    .superRefine((data, ctx) => {
      if (data.auth_mode === 'token') {
        if (!data.token_id.trim()) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['token_id'], message: t('AddHypervisorDialog.validation.tokenIdRequired') });
        }
        if (!data.token_secret.trim()) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['token_secret'], message: t('AddHypervisorDialog.validation.tokenSecretRequired') });
        }
      } else {
        if (!data.username.trim()) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['username'], message: t('AddHypervisorDialog.validation.usernameRequired') });
        }
        if (!data.password) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['password'], message: t('AddHypervisorDialog.validation.passwordRequired') });
        }
      }
    });
type HypervisorFormValues = z.infer<ReturnType<typeof buildSchema>>;

const defaultValues: HypervisorFormValues = {
  name: '',
  site_id: '',
  host: '',
  port: 8006,
  use_ssl: true,
  verify_ssl: false,
  sync_enabled: true,
  sync_interval_seconds: 300,
  auth_mode: 'token',
  token_id: '',
  token_secret: '',
  username: '',
  password: '',
  realm: 'pam',
};

export function AddHypervisorDialog({ open, onOpenChange }: AddHypervisorDialogProps) {
  const { t } = useTranslation('hypervisor');
  const queryClient = useQueryClient();
  const [showSecret, setShowSecret] = useState(false);
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [isTesting, setIsTesting] = useState(false);
  const [testError, setTestError] = useState<string | null>(null);

  const schema = buildSchema(t);

  const { data: sitesData } = useQuery({
    queryKey: ['sites'],
    queryFn: async () => {
      const response = await sitesApi.getAll();
      return response.data;
    },
  });

  const sites = sitesData?.items || [];

  const createMutation = useMutation({
    mutationFn: async (data: HypervisorFormValues) => {
      const config: Record<string, string> = { realm: data.realm || 'pam' };
      if (data.auth_mode === 'token') {
        config.token_id = data.token_id;
        config.token_secret = data.token_secret;
      }
      return controllersApi.create({
        name: data.name,
        site_id: data.site_id,
        controller_type: 'proxmox',
        host: data.host,
        port: data.port,
        username: data.auth_mode === 'password' ? data.username : '',
        password: data.auth_mode === 'password' ? data.password : '',
        use_ssl: data.use_ssl,
        verify_ssl: data.verify_ssl,
        sync_enabled: data.sync_enabled,
        sync_interval_seconds: data.sync_interval_seconds,
        config,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['controllers'] });
      onOpenChange(false);
    },
  });

  const handleOpenChange = (next: boolean) => {
    if (!next) {
      // Clear ephemeral test state on close so it doesn't persist on reopen.
      setShowSecret(false);
      setTestResult(null);
      setTestError(null);
      setIsTesting(false);
    }
    onOpenChange(next);
  };

  return (
    <FormDialog<HypervisorFormValues>
      open={open}
      onOpenChange={handleOpenChange}
      title={t('AddHypervisorDialog.title')}
      description={t('AddHypervisorDialog.description')}
      schema={schema}
      defaultValues={defaultValues}
      submitLabel={t('AddHypervisorDialog.submitLabel')}
      contentClassName="sm:max-w-[520px] max-h-[85vh] overflow-y-auto"
      onSubmit={async (values) => {
        await createMutation.mutateAsync(values);
      }}
    >
      {(form) => {
        const handleTestConnection = async () => {
          // Trigger validation but allow test even if some fields aren't filled
          // (we read raw values via form.getValues)
          const v = form.getValues();
          if (!v.host || !v.host.trim()) {
            setTestError(t('AddHypervisorDialog.validation.hostRequired'));
            return;
          }
          if (v.auth_mode === 'token') {
            if (!v.token_id.trim() || !v.token_secret.trim()) {
              setTestError(t('AddHypervisorDialog.validation.tokenIdAndSecretRequired'));
              return;
            }
          } else {
            if (!v.username.trim() || !v.password) {
              setTestError(t('AddHypervisorDialog.validation.usernameAndPasswordRequired'));
              return;
            }
          }

          setIsTesting(true);
          setTestResult(null);
          setTestError(null);
          try {
            const payload: Record<string, unknown> = {
              controller_type: 'proxmox',
              host: v.host,
              port: v.port,
              username: v.auth_mode === 'password' ? v.username : '',
              password: v.auth_mode === 'password' ? v.password : '',
              use_ssl: v.use_ssl,
              verify_ssl: v.verify_ssl,
              realm: v.realm,
            };
            if (v.auth_mode === 'token') {
              payload.token_id = v.token_id;
              payload.token_secret = v.token_secret;
            }
            const response = await controllersApi.testConnection(payload);
            setTestResult(response.data);
            if (!response.data.success) {
              setTestError(response.data.error || response.data.message || t('AddHypervisorDialog.test.failed'));
            }
          } catch (err: unknown) {
            const axiosErr = err as import('axios').AxiosError<{ detail?: string }>;
            const errObj = err as { message?: string };
            const detail = axiosErr.response?.data?.detail || errObj.message || t('AddHypervisorDialog.test.failed');
            setTestResult({ success: false, message: detail, error: detail });
            setTestError(detail);
          } finally {
            setIsTesting(false);
          }
        };

        const authMode = form.watch('auth_mode');
        const host = form.watch('host');
        const tokenId = form.watch('token_id');
        const tokenSecret = form.watch('token_secret');
        const username = form.watch('username');
        const password = form.watch('password');

        const testDisabled = isTesting || !host || (
          authMode === 'token'
            ? (!tokenId || !tokenSecret)
            : (!username || !password)
        );

        return (
          <>
            <div className="flex items-center gap-2 text-sm font-medium pb-2 -mt-2">
              <Server className="h-5 w-5" />
              <span>{t('AddHypervisorDialog.proxmoxVe')}</span>
            </div>

            {/* Name */}
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('AddHypervisorDialog.fields.name')}</FormLabel>
                  <FormControl>
                    <Input placeholder={t('AddHypervisorDialog.placeholders.name')} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* Site */}
            <FormField
              control={form.control}
              name="site_id"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('AddHypervisorDialog.fields.site')}</FormLabel>
                  <Select value={field.value} onValueChange={field.onChange}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder={t('AddHypervisorDialog.placeholders.site')} />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {sites.map((site: { id: string; name: string }) => (
                        <SelectItem key={site.id} value={site.id}>{site.name}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* Host & Port */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="sm:col-span-2">
                <FormField
                  control={form.control}
                  name="host"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t('AddHypervisorDialog.fields.host')}</FormLabel>
                      <FormControl>
                        <Input placeholder={t('AddHypervisorDialog.placeholders.host')} {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>
              <FormField
                control={form.control}
                name="port"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('AddHypervisorDialog.fields.port')}</FormLabel>
                    <FormControl>
                      <Input type="number" min={1} max={65535} {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            {/* Auth Mode Toggle */}
            <FormField
              control={form.control}
              name="auth_mode"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('AddHypervisorDialog.fields.authMethod')}</FormLabel>
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      className={`flex items-center justify-center gap-2 rounded-md border p-3 text-sm transition-colors ${
                        field.value === 'token'
                          ? 'border-primary bg-primary/10 text-primary font-medium'
                          : 'border-border hover:bg-accent'
                      }`}
                      onClick={() => field.onChange('token')}
                    >
                      {t('AddHypervisorDialog.authModes.token')}
                    </button>
                    <button
                      type="button"
                      className={`flex items-center justify-center gap-2 rounded-md border p-3 text-sm transition-colors ${
                        field.value === 'password'
                          ? 'border-primary bg-primary/10 text-primary font-medium'
                          : 'border-border hover:bg-accent'
                      }`}
                      onClick={() => field.onChange('password')}
                    >
                      {t('AddHypervisorDialog.authModes.password')}
                    </button>
                  </div>
                  <FormDescription>
                    {field.value === 'token'
                      ? t('AddHypervisorDialog.authDescriptions.token')
                      : t('AddHypervisorDialog.authDescriptions.password')}
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* Token Fields */}
            {authMode === 'token' && (
              <>
                <FormField
                  control={form.control}
                  name="token_id"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t('AddHypervisorDialog.fields.tokenId')}</FormLabel>
                      <FormControl>
                        <Input placeholder={t('AddHypervisorDialog.placeholders.tokenId')} {...field} />
                      </FormControl>
                      <FormDescription>
                        {t('AddHypervisorDialog.tokenIdFormatPrefix')} <code className="text-xs">user@realm!tokenname</code>
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="token_secret"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t('AddHypervisorDialog.fields.tokenSecret')}</FormLabel>
                      <FormControl>
                        <div className="relative">
                          <Input
                            type={showSecret ? 'text' : 'password'}
                            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                            {...field}
                          />
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
                            onClick={() => setShowSecret(!showSecret)}
                          >
                            {showSecret ? <EyeOff className="h-4 w-4 text-muted-foreground" /> : <Eye className="h-4 w-4 text-muted-foreground" />}
                          </Button>
                        </div>
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </>
            )}

            {/* Password Fields */}
            {authMode === 'password' && (
              <>
                <FormField
                  control={form.control}
                  name="username"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t('AddHypervisorDialog.fields.username')}</FormLabel>
                      <FormControl>
                        <Input placeholder="root" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="password"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{t('AddHypervisorDialog.fields.password')}</FormLabel>
                      <FormControl>
                        <div className="relative">
                          <Input
                            type={showSecret ? 'text' : 'password'}
                            placeholder="••••••••"
                            {...field}
                          />
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
                            onClick={() => setShowSecret(!showSecret)}
                          >
                            {showSecret ? <EyeOff className="h-4 w-4 text-muted-foreground" /> : <Eye className="h-4 w-4 text-muted-foreground" />}
                          </Button>
                        </div>
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </>
            )}

            {/* Realm */}
            <FormField
              control={form.control}
              name="realm"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('AddHypervisorDialog.fields.realm')}</FormLabel>
                  <Select value={field.value} onValueChange={field.onChange}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {PROXMOX_REALMS.map((r) => (
                        <SelectItem key={r.value} value={r.value}>{t(`AddHypervisorDialog.realms.${r.labelKey}`)}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* SSL Options */}
            <FormField
              control={form.control}
              name="use_ssl"
              render={({ field }) => (
                <FormItem>
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <FormLabel>{t('AddHypervisorDialog.fields.useSsl')}</FormLabel>
                      <p className="text-xs text-muted-foreground">{t('AddHypervisorDialog.fields.useSslHint')}</p>
                    </div>
                    <FormControl>
                      <Switch checked={field.value} onCheckedChange={field.onChange} />
                    </FormControl>
                  </div>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="verify_ssl"
              render={({ field }) => (
                <FormItem>
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <FormLabel>{t('AddHypervisorDialog.fields.verifySsl')}</FormLabel>
                      <p className="text-xs text-muted-foreground">{t('AddHypervisorDialog.fields.verifySslHint')}</p>
                    </div>
                    <FormControl>
                      <Switch checked={field.value} onCheckedChange={field.onChange} />
                    </FormControl>
                  </div>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* Test Connection */}
            <div className="space-y-3 rounded-lg border border-dashed p-3">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label className="text-sm font-medium">{t('AddHypervisorDialog.test.heading')}</Label>
                  <p className="text-xs text-muted-foreground">{t('AddHypervisorDialog.test.hint')}</p>
                </div>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={handleTestConnection}
                  disabled={testDisabled}
                >
                  {isTesting ? (
                    <><Loader2 className="mr-2 h-4 w-4 animate-spin" />{t('AddHypervisorDialog.test.testing')}</>
                  ) : (
                    <><TestTube className="mr-2 h-4 w-4" />{t('AddHypervisorDialog.test.button')}</>
                  )}
                </Button>
              </div>

              {testResult && (
                <div className={`rounded-md p-3 text-sm space-y-2 ${
                  testResult.success
                    ? 'bg-emerald-500/10 border border-emerald-500/20'
                    : 'bg-destructive/10 border border-destructive/20'
                }`}>
                  <div className="flex items-center gap-2 font-medium">
                    {testResult.success ? (
                      <><CheckCircle className="h-4 w-4 text-emerald-500" /><span className="text-emerald-700 dark:text-emerald-400">{t('AddHypervisorDialog.test.successful')}</span></>
                    ) : (
                      <><XCircle className="h-4 w-4 text-destructive" /><span className="text-destructive">{t('AddHypervisorDialog.test.failedLabel')}</span></>
                    )}
                  </div>
                  {testResult.success && testResult.details && (
                    <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-muted-foreground">
                      {testResult.details.latency_ms != null && (
                        <><span className="flex items-center gap-1"><Zap className="h-3 w-3" /> {t('AddHypervisorDialog.test.latency')}</span><span className="font-medium text-foreground">{t('AddHypervisorDialog.test.latencyValue', { value: testResult.details.latency_ms })}</span></>
                      )}
                      {testResult.details.controller_version && (
                        <><span className="flex items-center gap-1"><Info className="h-3 w-3" /> {t('AddHypervisorDialog.test.version')}</span><span className="font-medium text-foreground">{testResult.details.controller_version}</span></>
                      )}
                    </div>
                  )}
                  {!testResult.success && testResult.error && (
                    <p className="text-xs text-destructive/80 whitespace-pre-line">{testResult.error}</p>
                  )}
                </div>
              )}

              {testError && !testResult && (
                <div className="flex gap-2 rounded-md bg-destructive/10 p-3 text-sm text-destructive">
                  <XCircle className="h-4 w-4 shrink-0 mt-0.5" />
                  <div className="whitespace-pre-line">{testError}</div>
                </div>
              )}
            </div>
          </>
        );
      }}
    </FormDialog>
  );
}
