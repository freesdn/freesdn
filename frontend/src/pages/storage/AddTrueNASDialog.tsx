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

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { HardDrive, Eye, EyeOff, XCircle, CheckCircle, TestTube, Loader2, Info } from 'lucide-react';
import { z } from 'zod';
import { FormDialog } from '@/components/ui/form-dialog';
import { FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { controllersApi, sitesApi } from '@/lib/api';

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

const schema = z.object({
  name: z.string().min(1, 'Name is required'),
  site_id: z.string().min(1, 'Site is required'),
  host: z.string().min(1, 'Host is required'),
  port: z.coerce.number().int().min(1).max(65535),
  verify_ssl: z.boolean(),
  sync_enabled: z.boolean(),
  sync_interval_seconds: z.coerce.number().int().positive(),
  username: z.string().min(1, 'Username is required'),
  api_key: z.string().min(1, 'API key is required'),
});
type TrueNASFormValues = z.infer<typeof schema>;

const defaultValues: TrueNASFormValues = {
  name: '',
  site_id: '',
  host: '',
  port: 443,
  verify_ssl: false,
  sync_enabled: true,
  sync_interval_seconds: 300,
  username: 'truenas_admin',
  api_key: '',
};

export function AddTrueNASDialog({ open, onOpenChange }: AddTrueNASDialogProps) {
  const queryClient = useQueryClient();
  const [showKey, setShowKey] = useState(false);
  const [testResult, setTestResult] = useState<TestResult | null>(null);
  const [isTesting, setIsTesting] = useState(false);

  const { data: sitesData } = useQuery({
    queryKey: ['sites'],
    queryFn: async () => (await sitesApi.getAll()).data,
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
      title="Add TrueNAS Storage"
      description="Connect a TrueNAS appliance (SCALE / CORE) read-only to surface pool health, capacity, and disks."
      schema={schema}
      defaultValues={defaultValues}
      submitLabel="Add Appliance"
      contentClassName="sm:max-w-[520px] max-h-[85vh] overflow-y-auto"
      onSubmit={async (values) => {
        await createMutation.mutateAsync(values);
      }}
    >
      {(form) => {
        const handleTestConnection = async () => {
          const v = form.getValues();
          if (!v.host?.trim() || !v.username?.trim() || !v.api_key) {
            setTestResult({ success: false, message: 'Host, username and API key are required to test' });
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
            const axiosErr = err as import('axios').AxiosError<{ detail?: string }>;
            const detail =
              axiosErr.response?.data?.detail ||
              (err as { message?: string }).message ||
              'Connection test failed';
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
              <span>TrueNAS Storage</span>
            </div>

            {/* Name */}
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Name</FormLabel>
                  <FormControl>
                    <Input placeholder="e.g. S4 (Backup NAS)" {...field} />
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
                  <FormLabel>Site</FormLabel>
                  <Select value={field.value} onValueChange={field.onChange}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder="Select a site" />
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
                      <FormLabel>Host</FormLabel>
                      <FormControl>
                        <Input placeholder="truenas.lan or 100.x.y.z" {...field} />
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
                    <FormLabel>Port</FormLabel>
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
                  <FormLabel>API Key Owner</FormLabel>
                  <FormControl>
                    <Input placeholder="truenas_admin" {...field} />
                  </FormControl>
                  <FormDescription>
                    The login-enabled account the API key belongs to. On TrueNAS 25.x the{' '}
                    <code>root</code> account is disabled by default, use <code>truenas_admin</code>.
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
                  <FormLabel>API Key</FormLabel>
                  <div className="relative">
                    <FormControl>
                      <Input
                        type={showKey ? 'text' : 'password'}
                        placeholder="3-…  (Credentials → API Keys)"
                        autoComplete="off"
                        {...field}
                      />
                    </FormControl>
                    <button
                      type="button"
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground"
                      onClick={() => setShowKey((s) => !s)}
                      tabIndex={-1}
                    >
                      {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                  <FormDescription>
                    Read-only is recommended. The connection always uses TLS, TrueNAS revokes any
                    key seen over a plaintext connection.
                  </FormDescription>
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
                    <FormLabel>Verify TLS certificate</FormLabel>
                    <FormDescription>Leave off for the default self-signed appliance cert.</FormDescription>
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
                  <><Loader2 className="h-4 w-4 animate-spin mr-2" /> Testing…</>
                ) : (
                  <><TestTube className="h-4 w-4 mr-2" /> Test Connection</>
                )}
              </Button>
              {testResult && (
                <div
                  className={`flex items-start gap-2 rounded-md border p-3 text-sm ${
                    testResult.success
                      ? 'border-green-500/40 bg-green-500/10 text-green-700 dark:text-green-300'
                      : 'border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300'
                  }`}
                >
                  {testResult.success ? (
                    <CheckCircle className="h-4 w-4 mt-0.5 shrink-0" />
                  ) : (
                    <XCircle className="h-4 w-4 mt-0.5 shrink-0" />
                  )}
                  <div className="min-w-0">
                    <div className="font-medium">
                      {testResult.success ? 'Connection OK' : 'Connection failed'}
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
              <span>
                Read-only: FreeSDN never writes to the appliance. It surfaces ZFS pool health,
                capacity, disks and datasets in one pane.
              </span>
            </div>
          </>
        );
      }}
    </FormDialog>
  );
}

export default AddTrueNASDialog;
