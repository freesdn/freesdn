// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Plugin Detail Page
 *
 * Full detail view for a marketplace plugin: description, screenshots,
 * version history, reviews, and install/uninstall actions.
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ArrowLeft,
  Download,
  Star,
  Shield,
  Package,
  CheckCircle,
  Loader2,
  AlertCircle,
} from 'lucide-react';

import { api } from '@/lib/api';
import { useAuthStore } from '@/stores/authStore';
import { safeExternalUrl } from '@/lib/utils';
import { PageHeader } from '@/components/layout';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@/components/ui/accordion';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';
// NOTE: gate marketplace installs behind an explicit AlertDialog
// confirmation. The /install endpoint downloads third-party code and
// executes it with full backend privileges, a single accidental click
// is a supply-chain risk the user must acknowledge.
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog';


// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

interface PluginDetail {
  plugin_id: string;
  slug: string;
  name: string;
  short_description: string;
  description: string | null;
  author_name: string;
  author_url: string | null;
  category: string;
  tags: string[];
  latest_version: string;
  min_core_version: string;
  icon_url: string | null;
  banner_url: string | null;
  screenshots: string[];
  download_url: string;
  checksum_sha256: string;
  package_size: number | null;
  download_count: number;
  rating: number;
  rating_count: number;
  is_verified: boolean;
  is_featured: boolean;
}

interface InstalledPlugin {
  plugin_id: string;
  version: string;
  status: string;
}


// ─────────────────────────────────────────────────────────────────────────────
// Main Page
// ─────────────────────────────────────────────────────────────────────────────

export default function PluginDetailPage() {
  const { t } = useTranslation('marketplace');
  const { toast } = useToast();
  const { slug } = useParams<{ slug: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  // Install hard-gates on is_superuser server-side (403 otherwise). Hide the
  // control for non-superusers; the rest of the detail view stays browsable.
  const isSuperuser = useAuthStore((s) => s.user?.is_superuser ?? false);
  const [reviewBody, setReviewBody] = useState('');
  const [reviewRating, setReviewRating] = useState(5);
  const [reviewTitle, setReviewTitle] = useState('');

  const { data: plugin, isLoading, isError } = useQuery<PluginDetail>({
    queryKey: ['marketplace-plugin', slug],
    queryFn: () => api.get(`/marketplace/plugins/${slug}`).then((r) => r.data),
    enabled: !!slug,
  });

  const { data: versions } = useQuery<{ versions: Array<{ version: string; changelog: string; min_core_version: string; released_at: string }> }>({
    queryKey: ['marketplace-plugin-versions', slug],
    queryFn: () => api.get(`/marketplace/plugins/${slug}/versions`).then((r) => r.data),
    enabled: !!slug,
  });

  const { data: reviews } = useQuery<{ reviews: Array<{ id: string; rating: number; title: string | null; body: string | null; created_at: string }> }>({
    queryKey: ['marketplace-plugin-reviews', slug],
    queryFn: () => api.get(`/marketplace/plugins/${slug}/reviews`).then((r) => r.data),
    enabled: !!slug,
  });

  const { data: installedPlugins = [] } = useQuery<InstalledPlugin[]>({
    queryKey: ['plugins'],
    queryFn: () => api.get('/plugins').then((r) => r.data),
  });

  const installedPlugin = plugin
    ? installedPlugins.find((p) => p.plugin_id === plugin.plugin_id)
    : undefined;

  const installMutation = useMutation({
    mutationFn: () => api.post(`/marketplace/plugins/${slug}/install`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['plugins'] }),
  });

  const submitReviewMutation = useMutation({
    mutationFn: () =>
      api.post(`/marketplace/plugins/${slug}/reviews`, {
        rating: reviewRating,
        title: reviewTitle || undefined,
        body: reviewBody || undefined,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['marketplace-plugin-reviews', slug] });
      setReviewBody('');
      setReviewTitle('');
      setReviewRating(5);
      toast({ title: t('common:success') });
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 py-8 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        {t('PluginDetailPage.loading')}
      </div>
    );
  }

  if (isError || !plugin) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="h-4 w-4" />
        <AlertDescription>{t('PluginDetailPage.notFound')}</AlertDescription>
      </Alert>
    );
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <PageHeader
        icon={Package}
        title={plugin.name}
        subtitle={plugin.short_description}
        breadcrumbs={
          <button
            type="button"
            onClick={() => navigate('/marketplace')}
            className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            {t('PluginDetailPage.backToMarketplace')}
          </button>
        }
        actions={
          installedPlugin ? (
            <Button variant="outline" disabled>
              <CheckCircle className="mr-2 h-4 w-4 text-green-600" />
              {t('PluginDetailPage.installedWithVersion', { version: installedPlugin.version })}
            </Button>
          ) : !isSuperuser ? null : (
            // NOTE: wrap the install action in an AlertDialog so
            // the operator must explicitly acknowledge the supply-chain
            // risk before third-party code is downloaded and executed
            // with full backend privileges.
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button disabled={installMutation.isPending}>
                  {installMutation.isPending ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <Download className="mr-2 h-4 w-4" />
                  )}
                  {t('PluginDetailPage.install')}
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>
                    {t('PluginDetailPage.installDialog.title')}
                  </AlertDialogTitle>
                  <AlertDialogDescription>
                    {t('PluginDetailPage.installDialog.warning')}
                    <br />
                    <br />
                    {t('PluginDetailPage.installDialog.pluginLabel')}{' '}
                    <strong>{plugin.name}</strong> v{plugin.latest_version} {t('PluginDetailPage.by')} {plugin.author_name}
                    {plugin.is_verified ? null : (
                      <>
                        <br />
                        <br />
                        <span className="text-destructive font-medium">
                          {t('PluginDetailPage.installDialog.notVerified')}
                        </span>
                      </>
                    )}
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>{t('PluginDetailPage.installDialog.cancel')}</AlertDialogCancel>
                  <AlertDialogAction onClick={() => installMutation.mutate()}>
                    {t('PluginDetailPage.installDialog.confirm')}
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          )
        }
      />

      {/* Metadata: badges + author / version / rating / downloads */}
      <div className="space-y-2">
        <div className="flex items-center gap-2 flex-wrap">
          {plugin.is_verified && (
            <Badge className="bg-info/10 text-info border-info/20" variant="outline">
              <Shield className="mr-1 h-3 w-3" />
              {t('PluginDetailPage.verified')}
            </Badge>
          )}
          <Badge variant="secondary">{plugin.category}</Badge>
        </div>
        <div className="flex items-center gap-4 text-sm">
          <span>{t('PluginDetailPage.by')}{' '}
            {safeExternalUrl(plugin.author_url) ? (
              <a href={safeExternalUrl(plugin.author_url)!} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                {plugin.author_name}
              </a>
            ) : (
              plugin.author_name
            )}
          </span>
          <span className="text-muted-foreground">v{plugin.latest_version}</span>
          <span className="flex items-center gap-1 text-muted-foreground">
            <Star className="h-3.5 w-3.5 fill-yellow-400 text-yellow-400" />
            {t('PluginDetailPage.ratingSummary', { rating: plugin.rating.toFixed(1), count: plugin.rating_count })}
          </span>
          <span className="flex items-center gap-1 text-muted-foreground">
            <Download className="h-3.5 w-3.5" />
            {plugin.download_count.toLocaleString()}
          </span>
        </div>
      </div>

      {installMutation.isError && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>            {(installMutation.error as any)?.response?.data?.detail || t('PluginDetailPage.installFailed')}
          </AlertDescription>
        </Alert>
      )}

      {/* Description */}
      {plugin.description && (
        <div className="prose dark:prose-invert max-w-none">
          <pre className="whitespace-pre-wrap font-sans text-sm">{plugin.description}</pre>
        </div>
      )}

      {/* Screenshots */}
      {plugin.screenshots.length > 0 && (
        <div>
          <h2 className="mb-3 text-lg font-semibold">{t('PluginDetailPage.screenshots')}</h2>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            {plugin.screenshots.map((url, i) => (
              <img
                key={i}
                src={url}
                alt={t('PluginDetailPage.screenshotAlt', { index: i + 1 })}
                className="rounded-lg border object-cover"
              />
            ))}
          </div>
        </div>
      )}

      {/* Version history */}
      {versions && versions.versions.length > 0 && (
        <div>
          <h2 className="mb-3 text-lg font-semibold">{t('PluginDetailPage.versionHistory')}</h2>
          <Accordion type="single" collapsible className="space-y-2">
            {versions.versions.map((v) => (
              <AccordionItem key={v.version} value={v.version} className="rounded-lg border">
                <AccordionTrigger className="px-4 py-3 hover:no-underline">
                  <div className="flex items-center gap-3">
                    <Badge variant="outline">v{v.version}</Badge>
                    <span className="text-sm text-muted-foreground">
                      {new Date(v.released_at).toLocaleDateString()}
                    </span>
                  </div>
                </AccordionTrigger>
                <AccordionContent className="px-4 pb-3">
                  {v.changelog ? (
                    <pre className="whitespace-pre-wrap text-sm text-muted-foreground">{v.changelog}</pre>
                  ) : (
                    <p className="text-sm text-muted-foreground italic">{t('PluginDetailPage.noChangelog')}</p>
                  )}
                </AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
        </div>
      )}

      {/* Reviews */}
      <div>
        <h2 className="mb-4 text-lg font-semibold">{t('PluginDetailPage.reviews')}</h2>

        {reviews?.reviews.map((review) => (
          <div key={review.id} className="border-b py-4">
            <div className="flex items-center gap-2">
              <div className="flex">
                {[1, 2, 3, 4, 5].map((n) => (
                  <Star
                    key={n}
                    className={`h-4 w-4 ${n <= review.rating ? 'fill-yellow-400 text-yellow-400' : 'text-muted-foreground'}`}
                  />
                ))}
              </div>
              {review.title && <span className="font-medium">{review.title}</span>}
              <span className="text-xs text-muted-foreground">
                {new Date(review.created_at).toLocaleDateString()}
              </span>
            </div>
            {review.body && <p className="mt-2 text-sm text-muted-foreground">{review.body}</p>}
          </div>
        ))}

        {/* Submit review */}
        <div className="mt-4 space-y-3 rounded-lg border p-4">
          <h3 className="font-medium">{t('PluginDetailPage.writeReview')}</h3>
          <div className="flex gap-1">
            {[1, 2, 3, 4, 5].map((n) => (
              <button key={n} onClick={() => setReviewRating(n)}>
                <Star
                  className={`h-5 w-5 ${n <= reviewRating ? 'fill-yellow-400 text-yellow-400' : 'text-muted-foreground'} hover:fill-yellow-400 hover:text-yellow-400 transition-colors`}
                />
              </button>
            ))}
          </div>
          <Input
            placeholder={t('PluginDetailPage.writeReview')}
            value={reviewTitle}
            onChange={(e) => setReviewTitle(e.target.value)}
          />
          <Textarea
            placeholder={t('PluginDetailPage.reviewPlaceholder')}
            value={reviewBody}
            onChange={(e) => setReviewBody(e.target.value)}
            rows={3}
          />
          <Button
            size="sm"
            onClick={() => submitReviewMutation.mutate()}
            disabled={submitReviewMutation.isPending}
          >
            {submitReviewMutation.isPending && <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />}
            {t('PluginDetailPage.submitReview')}
          </Button>
          {submitReviewMutation.isError && (
            <p className="text-xs text-destructive">              {(submitReviewMutation.error as any)?.response?.data?.detail || t('PluginDetailPage.submitReviewFailed')}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
