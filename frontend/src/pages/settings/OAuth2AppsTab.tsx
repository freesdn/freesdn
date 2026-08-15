// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - OAuth2 Apps Settings Tab
 *
 * Allows users to register, view, and manage OAuth2 applications
 * that integrate with FreeSDN via the OAuth2 Authorization Code flow.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { z } from 'zod';
import {
  AppWindow,
  Plus,
  Trash2,
  Copy,
  Check,
  AlertTriangle,
  RotateCcw,
  ExternalLink,
} from 'lucide-react';

import { api } from '@/lib/api';
import { useToast } from '@/hooks/use-toast';
import { safeExternalUrl } from '@/lib/utils';
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
import { FormFieldArray } from '@/components/ui/form-field-array';
import {
  FormControl,
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

interface OAuth2App {
  id: string;
  name: string;
  description: string | null;
  client_id: string;
  client_secret_prefix: string;
  redirect_uris: string[];
  scopes: string[];
  grant_types: string[];
  is_active: boolean;
  is_confidential: boolean;
  logo_url: string | null;
  homepage_url: string | null;
  created_at: string;
}

interface OAuth2AppCreated extends OAuth2App {
  client_secret: string;
}


// ─────────────────────────────────────────────────────────────────────────────
// API helpers
// ─────────────────────────────────────────────────────────────────────────────

const oauth2Api = {
  list: () => api.get<OAuth2App[]>('/oauth2/apps'),
  create: (data: Partial<OAuth2App>) => api.post<OAuth2AppCreated>('/oauth2/apps', data),
  delete: (id: string) => api.delete(`/oauth2/apps/${id}`),
  rotateSecret: (id: string) => api.post<OAuth2AppCreated>(`/oauth2/apps/${id}/rotate-secret`),
};


// ─────────────────────────────────────────────────────────────────────────────
// Secret Revealed Dialog
// ─────────────────────────────────────────────────────────────────────────────

function SecretRevealedDialog({
  app,
  onClose,
}: {
  app: OAuth2AppCreated;
  onClose: () => void;
}) {
  const { t } = useTranslation('settings');
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(app.client_secret);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Dialog open onOpenChange={onClose}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{t('OAuth2AppsTab.secretDialog.title')}</DialogTitle>
          <DialogDescription>
            {t('OAuth2AppsTab.secretDialog.copyNow')} <strong>{t('OAuth2AppsTab.secretDialog.notShownAgain')}</strong>
          </DialogDescription>
        </DialogHeader>

        <Alert className="border-warning/40 bg-warning/10 text-warning [&>svg]:text-warning">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            {t('OAuth2AppsTab.secretDialog.storeSecurely')}
          </AlertDescription>
        </Alert>

        <div className="space-y-3">
          <div className="space-y-1">
            <Label className="text-xs text-muted-foreground">{t('OAuth2AppsTab.fields.clientId')}</Label>
            <code className="block text-xs bg-muted rounded px-2 py-1.5 font-mono break-all">
              {app.client_id}
            </code>
          </div>
          <div className="space-y-1">
            <Label className="text-xs text-muted-foreground">{t('OAuth2AppsTab.fields.clientSecret')}</Label>
            <div className="flex gap-2">
              <Input
                value={app.client_secret}
                readOnly
                className="font-mono text-xs"
              />
              <Button variant="outline" size="icon" onClick={handleCopy}>
                {copied ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
              </Button>
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button onClick={onClose}>{t('OAuth2AppsTab.secretDialog.stored')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}


// ─────────────────────────────────────────────────────────────────────────────
// Register App Dialog
// ─────────────────────────────────────────────────────────────────────────────

const buildRegisterAppSchema = (t: (key: string) => string) =>
  z.object({
    name: z.string().trim().min(1, t('OAuth2AppsTab.validation.nameRequired')),
    description: z.string(),
    redirect_uris: z
      .array(z.object({ value: z.string().trim().min(1, t('OAuth2AppsTab.validation.uriRequired')) }))
      .min(1, t('OAuth2AppsTab.validation.atLeastOneUri')),
    homepage_url: z.string(),
  });
type RegisterAppFormValues = z.infer<ReturnType<typeof buildRegisterAppSchema>>;

function RegisterAppDialog({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (app: OAuth2AppCreated) => void;
}) {
  const { t } = useTranslation('settings');
  const registerAppSchema = buildRegisterAppSchema(t);
  return (
    <FormDialog<RegisterAppFormValues>
      open
      onOpenChange={(next) => { if (!next) onClose(); }}
      title={t('OAuth2AppsTab.registerDialog.title')}
      description={t('OAuth2AppsTab.registerDialog.description')}
      schema={registerAppSchema}
      defaultValues={{
        name: '',
        description: '',
        redirect_uris: [{ value: '' }],
        homepage_url: '',
      }}
      submitLabel={t('OAuth2AppsTab.actions.registerApp')}
      contentClassName="max-w-lg"
      onSubmit={async (values) => {
        const response = await oauth2Api.create({
          name: values.name.trim(),
          description: values.description.trim() || undefined,
          redirect_uris: values.redirect_uris
            .map((u) => u.value.trim())
            .filter(Boolean),
          homepage_url: values.homepage_url.trim() || undefined,
        });
        onCreated(response.data);
      }}
    >
      {(form) => (
        <>
          <FormField
            control={form.control}
            name="name"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('OAuth2AppsTab.fields.applicationNameRequired')}</FormLabel>
                <FormControl>
                  <Input placeholder={t('OAuth2AppsTab.placeholders.applicationName')} {...field} />
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
                <FormLabel>{t('OAuth2AppsTab.fields.description')}</FormLabel>
                <FormControl>
                  <Textarea placeholder={t('OAuth2AppsTab.placeholders.description')} rows={2} {...field} />
                </FormControl>
              </FormItem>
            )}
          />
          <FormFieldArray<RegisterAppFormValues, 'redirect_uris'>
            control={form.control}
            name="redirect_uris"
            defaultItem={{ value: '' }}
            addLabel={t('OAuth2AppsTab.redirectUris.add')}
            label={t('OAuth2AppsTab.redirectUris.label')}
            description={t('OAuth2AppsTab.redirectUris.description')}
            minItems={1}
            emptyState={{ title: t('OAuth2AppsTab.redirectUris.empty') }}
          >
            {(_item, index, { remove, removeDisabled }) => (
              <div className="flex gap-2 items-start">
                <FormField
                  control={form.control}
                  name={`redirect_uris.${index}.value` as const}
                  render={({ field }) => (
                    <FormItem className="flex-1">
                      <FormLabel className="sr-only">{t('OAuth2AppsTab.redirectUris.itemLabel', { index: index + 1 })}</FormLabel>
                      <FormControl>
                        <Input
                          placeholder={t('OAuth2AppsTab.placeholders.redirectUri')}
                          className="font-mono text-xs"
                          {...field}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  onClick={() => remove()}
                  disabled={removeDisabled}
                  aria-label={t('OAuth2AppsTab.redirectUris.removeAria', { index: index + 1 })}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
            )}
          </FormFieldArray>
          <FormField
            control={form.control}
            name="homepage_url"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('OAuth2AppsTab.fields.homepageUrl')}</FormLabel>
                <FormControl>
                  <Input placeholder={t('OAuth2AppsTab.placeholders.homepageUrl')} {...field} />
                </FormControl>
              </FormItem>
            )}
          />
        </>
      )}
    </FormDialog>
  );
}


// ─────────────────────────────────────────────────────────────────────────────
// Main Tab
// ─────────────────────────────────────────────────────────────────────────────

export function OAuth2AppsTab() {
  const { t } = useTranslation('settings');
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [showRegister, setShowRegister] = useState(false);
  const [revealedApp, setRevealedApp] = useState<OAuth2AppCreated | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const { data: apps = [], isLoading, isError } = useQuery({
    queryKey: ['oauth2-apps'],
    queryFn: () => oauth2Api.list().then((r) => r.data),
    retry: false,
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => oauth2Api.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['oauth2-apps'] });
      setDeletingId(null);
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      toast({
        title: t('common:error'),
        description: err?.response?.data?.detail,
        variant: 'destructive',
      });
    },
  });

  const rotateMutation = useMutation({
    mutationFn: (id: string) => oauth2Api.rotateSecret(id),
    onSuccess: (response) => {
      setRevealedApp(response.data);
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    onError: (err: any) => {
      toast({
        title: t('common:error'),
        description: err?.response?.data?.detail,
        variant: 'destructive',
      });
    },
  });

  const handleCreated = (app: OAuth2AppCreated) => {
    queryClient.invalidateQueries({ queryKey: ['oauth2-apps'] });
    setShowRegister(false);
    setRevealedApp(app);
  };

  const formatDate = (iso: string) =>
    new Date(iso).toLocaleDateString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
    });

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>{t('OAuth2AppsTab.header.title')}</CardTitle>
            <CardDescription>
              {t('OAuth2AppsTab.header.description')}
            </CardDescription>
          </div>
          <Button onClick={() => setShowRegister(true)} size="sm" className="gap-2 shrink-0">
            <Plus className="h-4 w-4" />
            {t('OAuth2AppsTab.actions.registerApp')}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">

      {isError && (
        <Card className="border-destructive">
          <CardContent noOffset className="p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive" />
            <span className="text-sm">{t('OAuth2AppsTab.errors.loadFailed')}</span>
          </CardContent>
        </Card>
      )}

      {isLoading ? (
        <div className="py-8 text-center text-sm text-muted-foreground">{t('OAuth2AppsTab.loading')}</div>
      ) : apps.length === 0 ? (
        <EmptyState
          icon={AppWindow}
          title={t('OAuth2AppsTab.empty.title')}
          description={t('OAuth2AppsTab.empty.description')}
          action={{ label: t('OAuth2AppsTab.actions.registerApp'), onClick: () => setShowRegister(true), icon: Plus }}
        />
      ) : (
        <div className="space-y-2">
          {apps.map((app) => (
            <div key={app.id} className="rounded-lg border p-4">
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-3 min-w-0">
                  <AppWindow className="h-5 w-5 mt-0.5 text-muted-foreground shrink-0" />
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-medium text-sm">{app.name}</span>
                      {!app.is_active && (
                        <Badge variant="destructive" className="text-xs">{t('OAuth2AppsTab.status.inactive')}</Badge>
                      )}
                    </div>
                    {app.description && (
                      <p className="text-xs text-muted-foreground mt-0.5 truncate">
                        {app.description}
                      </p>
                    )}
                    <div className="mt-2 space-y-1">
                      <div className="flex items-center gap-2 text-xs">
                        <span className="text-muted-foreground">{t('OAuth2AppsTab.fields.clientIdLabel')}</span>
                        <code className="font-mono bg-muted px-1.5 py-0.5 rounded text-xs">
                          {app.client_id}
                        </code>
                      </div>
                      <div className="flex items-center gap-2 text-xs">
                        <span className="text-muted-foreground">{t('OAuth2AppsTab.fields.secretLabel')}</span>
                        <code className="font-mono bg-muted px-1.5 py-0.5 rounded text-xs">
                          {app.client_secret_prefix}…
                        </code>
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {(app.redirect_uris?.length ?? 0) === 1
                          ? t('OAuth2AppsTab.meta.redirectUriCount', { count: app.redirect_uris?.length ?? 0 })
                          : t('OAuth2AppsTab.meta.redirectUriCountPlural', { count: app.redirect_uris?.length ?? 0 })}
                        {' · '}
                        {t('OAuth2AppsTab.meta.registered', { date: formatDate(app.created_at) })}
                        {safeExternalUrl(app.homepage_url) && (
                          <>
                            {' · '}
                            <a
                              href={safeExternalUrl(app.homepage_url)!}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-0.5 hover:underline"
                            >
                              {t('OAuth2AppsTab.meta.website')} <ExternalLink className="h-3 w-3" />
                            </a>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-1 shrink-0">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="gap-1.5 text-xs"
                    title={t('OAuth2AppsTab.actions.rotateTitle')}
                    onClick={() => rotateMutation.mutate(app.id)}
                    disabled={rotateMutation.isPending}
                  >
                    <RotateCcw className="h-3.5 w-3.5" />
                    {t('OAuth2AppsTab.actions.rotate')}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-destructive hover:text-destructive hover:bg-destructive/10"
                    onClick={() => setDeletingId(app.id)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Register dialog */}
      {showRegister && (
        <RegisterAppDialog onClose={() => setShowRegister(false)} onCreated={handleCreated} />
      )}

      {/* Secret revealed */}
      {revealedApp && (
        <SecretRevealedDialog app={revealedApp} onClose={() => setRevealedApp(null)} />
      )}

      {/* Delete confirmation */}
      {deletingId && (
        <Dialog open onOpenChange={() => setDeletingId(null)}>
          <DialogContent className="max-w-sm">
            <DialogHeader>
              <DialogTitle>{t('OAuth2AppsTab.deleteDialog.title')}</DialogTitle>
              <DialogDescription>
                {t('OAuth2AppsTab.deleteDialog.description')}
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="outline" onClick={() => setDeletingId(null)}>
                {t('OAuth2AppsTab.actions.cancel')}
              </Button>
              <Button
                variant="destructive"
                onClick={() => deleteMutation.mutate(deletingId)}
                disabled={deleteMutation.isPending}
              >
                {deleteMutation.isPending ? t('OAuth2AppsTab.actions.deleting') : t('OAuth2AppsTab.actions.deleteApp')}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
      </CardContent>
    </Card>
  );
}
