// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Add TrueNAS Storage Dialog
 *
 * Built on the canonical FormDialog primitive (mirrors AddHypervisorDialog).
 * TrueNAS authenticates with an API key (entered in the password field);
 * the backend maps it to the adapter's api_key kwarg. TrueNAS 25.x speaks a
 * WebSocket JSON-RPC API and auto-revokes keys used over plaintext, so the
 * adapter connects over TLS only, the operator just supplies host + key.
 */

import { useMemo, useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HardDrive, Eye, EyeOff, XCircle, CheckCircle, TestTube, Loader2, Info } from 'lucide-react';
import { z } from 'zod';
import { FormDialog } from '@/components/ui/form-dialog';
import { FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { controllersApi, sitePickerQuery } from '@/lib/api';
import { getApiErrorMessage } from '@/lib/api/errors';

interface AddTrueNASDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface TestResult {
  success: boolean;
  message: string;
  error?: string;
  details?: { latency_ms?: number; controller_version?: string };
}

const buildSchema = (t: TFunction) =>
  z.object({
    name: z.string().min(1, t('addDialog.validation.name')),
    site_id: z.string().min(1, t('addDialog.validation.site')),
    host: z.string().min(1, t('addDialog.validation.host')),
    port: z.coerce.number().int().min(1).max(65535),
    verify_ssl: z.boolean(),
    sync_enabled: z.boolean(),
    sync_interval_seconds: z.coerce.number().int().positive(),
    username: z.string().min(1, t('addDialog.validation.username')),
    api_key: z.string().min(1, t('addDialog.validation.apiKey')),
  });
type TrueNASFormValues = z.infer<ReturnType<typeof buildSchema>>;

const defaultValues: TrueNASFormValues = {
  name: '',
  site_id: '',
  host: '',
  port: 443,
  verify_ssl: true,
  sync_enabled: true,
  sync_interval_seconds: 300,
  username: 'truenas_admin',
  api_key: '',
};

export function AddTrueNASDialog({ open, onOpenChange }: AddTrueNASDialogProps) {
  const { t } = useTranslation('storage');
  const schema = useMemo(() => buildSchema(t), [t]);
  const queryClient = useQueryClient();
  const [showKey, setShowKey] = useState(false);
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [isTesting, setIsTesting] = useState(false);

  const { data: sitesData } = useQuery({
    ...sitePickerQuery,
    // Load-bearing: the dialog stays MOUNTED between opens, so
    // refetchOnMount never fires. Toggling enabled on open is what
    // actually refetches, so a site created since last open appears.
    enabled: open,
  });
  const sites = sitesData?.items || [];

  const createMutation = useMutation({
    mutationFn: async (data: TrueNASFormValues) =>
      controllersApi.create({
        name: data.name,
        site_id: data.site_id,
        controller_type: 'truenas',
        host: data.host,
        port: data.port,
        username: data.username,
        // API key rides in the password field; the backend maps it to the
        // adapter's api_key kwarg (and encrypts it at rest).
        password: data.api_key,
        use_ssl: true,
        verify_ssl: data.verify_ssl,
        sync_enabled: data.sync_enabled,
        sync_interval_seconds: data.sync_interval_seconds,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['controllers'] });
      queryClient.invalidateQueries({ queryKey: ['storage-devices'] });
      onOpenChange(false);
    },
  });

  const handleOpenChange = (next: boolean) => {
    if (!next) {
      setShowKey(false);
      setTestResult(null);
      setIsTesting(false);
    }
    onOpenChange(next);
  };

  return (
    <FormDialog<TrueNASFormValues>
      open={open}
      onOpenChange={handleOpenChange}
      title={t('addDialog.title')}
      description={t('addDialog.description')}
      schema={schema}
      defaultValues={defaultValues}
      submitLabel={t('addDialog.submit')}
      contentClassName="sm:max-w-[520px] max-h-[85vh] overflow-y-auto"
      onSubmit={async (values) => {
        await createMutation.mutateAsync(values);
      }}
    >
      {(form) => {
        const handleTestConnection = async () => {
          const v = form.getValues();
          if (!v.host?.trim() || !v.username?.trim() || !v.api_key) {
            setTestResult({ success: false, message: t('addDialog.testNeedsFields') });
            return;
          }
          setIsTesting(true);
          setTestResult(null);
          try {
            const res = await controllersApi.testConnection({
              controller_type: 'truenas',
              host: v.host,
              port: v.port,
              username: v.username,
              password: v.api_key,
              use_ssl: true,
              verify_ssl: v.verify_ssl,
            });
            setTestResult(res.data);
          } catch (err: unknown) {
            const detail = getApiErrorMessage(err, t('addDialog.testFailed'));
            setTestResult({ success: false, message: detail, error: detail });
          } finally {
            setIsTesting(false);
          }
        };

        const host = form.watch('host');
        const username = form.watch('username');
        const apiKey = form.watch('api_key');
        const testDisabled = isTesting || !host || !username || !apiKey;

        return (
          <>
            <div className="flex items-center gap-2 text-sm font-medium pb-2 -mt-2">
              <HardDrive className="h-5 w-5" />
              <span>{t('addDialog.heading')}</span>
            </div>

            {/* Name */}
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('addDialog.name')}</FormLabel>
                  <FormControl>
                    <Input placeholder={t('addDialog.namePlaceholder')} {...field} />
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
                  <FormLabel>{t('addDialog.site')}</FormLabel>
                  <Select value={field.value} onValueChange={field.onChange}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder={t('addDialog.sitePlaceholder')} />
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
                      <FormLabel>{t('addDialog.host')}</FormLabel>
                      <FormControl>
                        <Input placeholder={t('addDialog.hostPlaceholder')} {...field} />
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
                    <FormLabel>{t('addDialog.port')}</FormLabel>
                    <FormControl>
                      <Input type="number" min={1} max={65535} {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            {/* Username (key owner) */}
            <FormField
              control={form.control}
              name="username"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('addDialog.keyOwner')}</FormLabel>
                  <FormControl>
                    <Input placeholder="truenas_admin" {...field} />
                  </FormControl>
                  <FormDescription>
                    <Trans i18nKey="addDialog.keyOwnerHelp" t={t} components={{ code: <code /> }} />
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* API key */}
            <FormField
              control={form.control}
              name="api_key"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('addDialog.apiKey')}</FormLabel>
                  <div className="relative">
                    <FormControl>
                      <Input
                        type={showKey ? 'text' : 'password'}
                        placeholder={t('addDialog.apiKeyPlaceholder')}
                        autoComplete="off"
                        {...field}
                      />
                    </FormControl>
                    <button
                      type="button"
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground"
                      onClick={() => setShowKey((s) => !s)}
                      aria-label={showKey ? t('addDialog.hideKey') : t('addDialog.showKey')}
                      aria-pressed={showKey}
                    >
                      {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                  <FormDescription>{t('addDialog.apiKeyHelp')}</FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* Verify SSL */}
            <FormField
              control={form.control}
              name="verify_ssl"
              render={({ field }) => (
                <FormItem className="flex items-center justify-between rounded-md border p-3">
                  <div className="space-y-0.5">
                    <FormLabel>{t('addDialog.verifyTls')}</FormLabel>
                    <FormDescription>{t('addDialog.verifyTlsHelp')}</FormDescription>
                  </div>
                  <FormControl>
                    <Switch checked={field.value} onCheckedChange={field.onChange} />
                  </FormControl>
                </FormItem>
              )}
            />

            {/* Test connection */}
            <div className="space-y-2">
              <Button
                type="button"
                variant="outline"
                className="w-full"
                onClick={handleTestConnection}
                disabled={testDisabled}
              >
                {isTesting ? (
                  <><Loader2 className="h-4 w-4 animate-spin mr-2" /> {t('addDialog.testing')}</>
                ) : (
                  <><TestTube className="h-4 w-4 mr-2" /> {t('addDialog.test')}</>
                )}
              </Button>
              {testResult && (
                <div
                  className={`flex items-start gap-2 rounded-md border p-3 text-sm ${
                    testResult.success
                      ? 'border-success/40 bg-success/10 text-success'
                      : 'border-destructive/40 bg-destructive/10 text-destructive'
                  }`}
                >
                  {testResult.success ? (
                    <CheckCircle className="h-4 w-4 mt-0.5 shrink-0" />
                  ) : (
                    <XCircle className="h-4 w-4 mt-0.5 shrink-0" />
                  )}
                  <div className="min-w-0">
                    <div className="font-medium">
                      {testResult.success ? t('addDialog.testOk') : t('addDialog.testFailed')}
                      {testResult.details?.controller_version
                        ? ` · ${testResult.details.controller_version}`
                        : ''}
                    </div>
                    <div className="break-words opacity-90">
                      {testResult.error || testResult.message}
                    </div>
                  </div>
                </div>
              )}
            </div>

            <div className="flex items-start gap-2 rounded-md border border-border bg-muted/40 p-3 text-xs text-muted-foreground">
              <Info className="h-4 w-4 mt-0.5 shrink-0" />
              <span>{t('addDialog.writesNote')}</span>
            </div>
          </>
        );
      }}
    </FormDialog>
  );
}

export default AddTrueNASDialog;
