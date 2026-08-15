// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - API Keys Settings Tab
 *
 * Allows users to create, view, and revoke API keys for programmatic access.
 * The full key is shown only once at creation time.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';
import type { TFunction } from 'i18next';
import {
  Key,
  Plus,
  Trash2,
  Copy,
  Check,
  AlertTriangle,
  Clock,
  ShieldCheck,
} from 'lucide-react';

import { api } from '@/lib/api';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { EmptyState } from '@/components/ui/empty-state';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
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
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import { Alert, AlertDescription } from '@/components/ui/alert';


// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface APIKey {
  id: string;
  name: string;
  key_prefix: string;
  description: string | null;
  scopes: string[];
  last_used: string | null;
  expires_at: string | null;
  is_active: boolean;
  created_at: string;
}

interface APIKeyCreated extends APIKey {
  key: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// API helpers
// ─────────────────────────────────────────────────────────────────────────────

const apiKeyApi = {
  list: () => api.get<APIKey[]>('/api-keys/'),
  create: (data: { name: string; description?: string; scopes: string[]; expires_in_days?: number }) =>
    api.post<APIKeyCreated>('/api-keys/', data),
  revoke: (id: string) => api.delete(`/api-keys/${id}`),
};


// ─────────────────────────────────────────────────────────────────────────────
// Key Created Dialog (shows full key once)
// ─────────────────────────────────────────────────────────────────────────────

function KeyCreatedDialog({
  apiKey,
  onClose,
}: {
  apiKey: APIKeyCreated;
  onClose: () => void;
}) {
  const { t } = useTranslation('settings');
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(apiKey.key);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Dialog open onOpenChange={onClose}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-green-500" />
            {t('APIKeysTab.created.title')}
          </DialogTitle>
          <DialogDescription>
            {t('APIKeysTab.created.description')} <strong>{t('APIKeysTab.created.notShownAgain')}</strong>
          </DialogDescription>
        </DialogHeader>

        <Alert className="border-warning/40 bg-warning/10 text-warning [&>svg]:text-warning">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            {t('APIKeysTab.created.storeSecurely')}
          </AlertDescription>
        </Alert>

        <div className="space-y-2">
          <Label>{t('APIKeysTab.created.keyLabel')}</Label>
          <div className="flex gap-2">
            <Input
              value={apiKey.key}
              readOnly
              className="font-mono text-sm"
            />
            <Button variant="outline" size="icon" onClick={handleCopy}>
              {copied ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
            </Button>
          </div>
        </div>

        <DialogFooter>
          <Button onClick={onClose}>{t('APIKeysTab.created.copiedConfirm')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}


// ─────────────────────────────────────────────────────────────────────────────
// Create Key Dialog
// ─────────────────────────────────────────────────────────────────────────────

const AVAILABLE_SCOPES = [
  { value: 'device:read', labelKey: 'scopes.deviceRead' },
  { value: 'device:write', labelKey: 'scopes.deviceWrite' },
  { value: 'network:read', labelKey: 'scopes.networkRead' },
  { value: 'network:write', labelKey: 'scopes.networkWrite' },
  { value: 'cameras:read', labelKey: 'scopes.camerasRead' },
  { value: 'cameras:write', labelKey: 'scopes.camerasWrite' },
  { value: 'backup:read', labelKey: 'scopes.backupRead' },
  { value: 'backup:write', labelKey: 'scopes.backupWrite' },
  { value: 'automation:read', labelKey: 'scopes.automationRead' },
  { value: 'automation:write', labelKey: 'scopes.automationWrite' },
];

const buildCreateKeySchema = (t: TFunction) =>
  z.object({
    name: z.string().trim().min(1, t('APIKeysTab.validation.nameRequired')),
    description: z.string(),
    scopes: z.array(z.string()),
    expires_in_days: z.string().refine(
      (v) => v === '' || (/^\d+$/.test(v) && Number(v) >= 1 && Number(v) <= 365),
      { message: t('APIKeysTab.validation.expiresRange') },
    ),
  });
type CreateKeyFormValues = z.infer<ReturnType<typeof buildCreateKeySchema>>;

function CreateKeyDialog({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (key: APIKeyCreated) => void;
}) {
  const { t } = useTranslation('settings');
  return (
    <FormDialog<CreateKeyFormValues>
      open
      onOpenChange={(next) => { if (!next) onClose(); }}
      title={t('APIKeysTab.create.title')}
      description={t('APIKeysTab.create.description')}
      schema={buildCreateKeySchema(t)}
      defaultValues={{ name: '', description: '', scopes: [], expires_in_days: '' }}
      submitLabel={t('APIKeysTab.create.submit')}
      contentClassName="max-w-lg"
      onSubmit={async (values) => {
        const response = await apiKeyApi.create({
          name: values.name.trim(),
          description: values.description.trim() || undefined,
          scopes: values.scopes,
          expires_in_days: values.expires_in_days ? parseInt(values.expires_in_days, 10) : undefined,
        });
        onCreated(response.data);
      }}
    >
      {(form) => {
        const scopes = form.watch('scopes');
        const toggleScope = (scope: string) => {
          form.setValue(
            'scopes',
            scopes.includes(scope) ? scopes.filter((s) => s !== scope) : [...scopes, scope],
          );
        };

        return (
          <>
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('APIKeysTab.create.nameLabel')}</FormLabel>
                  <FormControl>
                    <Input placeholder={t('APIKeysTab.create.namePlaceholder')} {...field} />
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
                  <FormLabel>{t('APIKeysTab.create.descriptionLabel')}</FormLabel>
                  <FormControl>
                    <Textarea placeholder={t('APIKeysTab.create.descriptionPlaceholder')} rows={2} {...field} />
                  </FormControl>
                </FormItem>
              )}
            />
            <FormItem>
              <FormLabel>{t('APIKeysTab.create.scopesLabel')}</FormLabel>
              <FormDescription>
                {t('APIKeysTab.create.scopesDescription')}
              </FormDescription>
              <div className="grid grid-cols-2 gap-1.5 rounded-md border p-3">
                {AVAILABLE_SCOPES.map((scope) => (
                  <label
                    key={scope.value}
                    className="flex items-center gap-2 cursor-pointer text-sm"
                  >
                    <input
                      type="checkbox"
                      checked={scopes.includes(scope.value)}
                      onChange={() => toggleScope(scope.value)}
                      className="h-3.5 w-3.5"
                    />
                    {t(`APIKeysTab.${scope.labelKey}`)}
                  </label>
                ))}
              </div>
            </FormItem>
            <FormField
              control={form.control}
              name="expires_in_days"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>{t('APIKeysTab.create.expiresLabel')}</FormLabel>
                  <FormControl>
                    <Input
                      type="number"
                      min={1}
                      max={365}
                      placeholder={t('APIKeysTab.create.expiresPlaceholder')}
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </>
        );
      }}
    </FormDialog>
  );
}


// ─────────────────────────────────────────────────────────────────────────────
// Main Tab
// ─────────────────────────────────────────────────────────────────────────────

export function APIKeysTab() {
  const { t } = useTranslation('settings');
  const queryClient = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [createdKey, setCreatedKey] = useState<APIKeyCreated | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);

  const { data: keys = [], isLoading, isError } = useQuery({
    queryKey: ['api-keys'],
    queryFn: () => apiKeyApi.list().then((r) => r.data),
    retry: false,
  });

  const revokeMutation = useMutation({
    mutationFn: (id: string) => apiKeyApi.revoke(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] });
      setRevokingId(null);
    },
    onError: () => {
      // Error is shown via the dialog remaining open
    },
  });

  const handleCreated = (key: APIKeyCreated) => {
    queryClient.invalidateQueries({ queryKey: ['api-keys'] });
    setShowCreate(false);
    setCreatedKey(key);
  };

  const formatDate = (iso: string) =>
    new Date(iso).toLocaleDateString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
    });

  const isExpired = (expiresAt: string | null) =>
    expiresAt ? new Date(expiresAt) < new Date() : false;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>{t('APIKeysTab.header.title')}</CardTitle>
            <CardDescription>
              {t('APIKeysTab.header.description')}
            </CardDescription>
          </div>
          <Button onClick={() => setShowCreate(true)} size="sm" className="gap-2 shrink-0">
            <Plus className="h-4 w-4" />
            {t('APIKeysTab.header.newKey')}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">

      {isError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('APIKeysTab.loadError')}</span>
          </CardContent>
        </Card>
      )}

      {isLoading ? (
        <div className="py-8 text-center text-sm text-muted-foreground">{t('APIKeysTab.loading')}</div>
      ) : keys.length === 0 ? (
        <EmptyState
          icon={Key}
          title={t('APIKeysTab.empty.title')}
          description={t('APIKeysTab.empty.description')}
          action={{ label: t('APIKeysTab.empty.action'), onClick: () => setShowCreate(true), icon: Plus }}
        />
      ) : (
        <div className="space-y-2">
          {keys.map((key) => {
            const expired = isExpired(key.expires_at);
            return (
              <div
                key={key.id}
                className="flex items-center justify-between gap-4 rounded-lg border p-4"
              >
                <div className="flex items-start gap-3 min-w-0">
                  <Key className="h-5 w-5 mt-0.5 text-muted-foreground shrink-0" />
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-medium text-sm">{key.name}</span>
                      <code className="text-xs bg-muted px-1.5 py-0.5 rounded font-mono">
                        {key.key_prefix}…
                      </code>
                      {!key.is_active && (
                        <Badge variant="destructive" className="text-xs">{t('APIKeysTab.badge.revoked')}</Badge>
                      )}
                      {expired && (
                        <Badge variant="secondary" className="text-xs">{t('APIKeysTab.badge.expired')}</Badge>
                      )}
                    </div>
                    {key.description && (
                      <p className="text-xs text-muted-foreground mt-0.5 truncate">
                        {key.description}
                      </p>
                    )}
                    <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                      {(key.scopes?.length ?? 0) > 0 && (
                        <span>
                          {key.scopes.length === 1
                            ? t('APIKeysTab.scopeCount.one', { count: key.scopes.length })
                            : t('APIKeysTab.scopeCount.other', { count: key.scopes.length })}
                        </span>
                      )}
                      {key.last_used ? (
                        <span className="flex items-center gap-1">
                          <Clock className="h-3 w-3" />
                          {t('APIKeysTab.lastUsed', { date: formatDate(key.last_used) })}
                        </span>
                      ) : (
                        <span>{t('APIKeysTab.neverUsed')}</span>
                      )}
                      {key.expires_at && (
                        <span className={expired ? 'text-destructive' : ''}>
                          {expired
                            ? t('APIKeysTab.expiredOn', { date: formatDate(key.expires_at) })
                            : t('APIKeysTab.expiresOn', { date: formatDate(key.expires_at) })}
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {key.is_active && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-destructive hover:text-destructive hover:bg-destructive/10 shrink-0"
                    onClick={() => setRevokingId(key.id)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Create Dialog */}
      {showCreate && (
        <CreateKeyDialog onClose={() => setShowCreate(false)} onCreated={handleCreated} />
      )}

      {/* Created key · show full key once */}
      {createdKey && (
        <KeyCreatedDialog
          apiKey={createdKey}
          onClose={() => setCreatedKey(null)}
        />
      )}

      {/* Revoke confirmation */}
      {revokingId && (
        <Dialog open onOpenChange={() => setRevokingId(null)}>
          <DialogContent className="max-w-sm">
            <DialogHeader>
              <DialogTitle>{t('APIKeysTab.revoke.title')}</DialogTitle>
              <DialogDescription>
                {t('APIKeysTab.revoke.description')}
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="outline" onClick={() => setRevokingId(null)}>
                {t('APIKeysTab.revoke.cancel')}
              </Button>
              <Button
                variant="destructive"
                onClick={() => revokeMutation.mutate(revokingId)}
                disabled={revokeMutation.isPending}
              >
                {revokeMutation.isPending ? t('APIKeysTab.revoke.revoking') : t('APIKeysTab.revoke.confirm')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
      </CardContent>
    </Card>
  );
}
