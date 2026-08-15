// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Edit Controller Modal
 *
 * Modal dialog for editing existing network controllers.
 * Built on the canonical FormDialog primitive.
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { z } from 'zod';
import { Server } from 'lucide-react';
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
import { Switch } from '@/components/ui/switch';
import { Textarea } from '@/components/ui/textarea';
import { controllersApi, sitesApi } from '@/lib/api';

interface Controller {
  id: string;
  name: string;
  description: string | null;
  controller_type: string;
  host: string;
  port: number;
  use_ssl: boolean;
  verify_ssl: boolean;
  sync_enabled: boolean;
  sync_interval_seconds: number;
  is_active: boolean;
  site_id: string;
}

interface EditControllerModalProps {
  controller: Controller | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const buildSchema = (t: (key: string) => string) =>
  z.object({
    name: z.string().trim().min(1, t('EditControllerModal.validation.nameRequired')),
    description: z.string(),
    host: z.string().trim().min(1, t('EditControllerModal.validation.hostRequired')),
    port: z.coerce
      .number()
      .int()
      .min(1, t('EditControllerModal.validation.portRange'))
      .max(65535, t('EditControllerModal.validation.portRange')),
    use_ssl: z.boolean(),
    verify_ssl: z.boolean(),
    sync_enabled: z.boolean(),
    sync_interval_seconds: z.coerce.number().int().min(60, t('EditControllerModal.validation.minSeconds')),
    is_active: z.boolean(),
  });
type EditFormValues = z.infer<ReturnType<typeof buildSchema>>;

export function EditControllerModal({ controller, open, onOpenChange }: EditControllerModalProps) {
  const { t } = useTranslation('common');
  const queryClient = useQueryClient();
  const schema = buildSchema(t);

  // Fetch sites for reference (display only · site_id is immutable here)
  const { data: sitesData } = useQuery({
    queryKey: ['sites'],
    queryFn: async () => {
      const response = await sitesApi.getAll();
      return response.data;
    },
    enabled: open,
  });

  const sites = sitesData?.items || [];
  const siteName = sites.find((s: { id: string; name: string }) => s.id === controller?.site_id)?.name || t('EditControllerModal.unknownSite');

  const updateMutation = useMutation({
    mutationFn: async (data: EditFormValues) => {
      if (!controller) throw new Error('No controller selected');
      return controllersApi.update(controller.id, {
        name: data.name,
        description: data.description || null,
        host: data.host,
        port: data.port,
        use_ssl: data.use_ssl,
        verify_ssl: data.verify_ssl,
        sync_enabled: data.sync_enabled,
        sync_interval_seconds: data.sync_interval_seconds,
        is_active: data.is_active,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['controllers'] });
      onOpenChange(false);
    },
  });

  if (!controller) return null;

  const defaultValues: EditFormValues = {
    name: controller.name,
    description: controller.description || '',
    host: controller.host,
    port: controller.port,
    use_ssl: controller.use_ssl,
    verify_ssl: controller.verify_ssl,
    sync_enabled: controller.sync_enabled,
    sync_interval_seconds: controller.sync_interval_seconds,
    is_active: controller.is_active,
  };

  return (
    <FormDialog<EditFormValues>
      open={open}
      onOpenChange={onOpenChange}
      title={t('EditControllerModal.title')}
      description={t('EditControllerModal.description', { name: controller.name })}
      schema={schema}
      defaultValues={defaultValues}
      onSubmit={async (values) => {
        await updateMutation.mutateAsync(values);
      }}
      submitLabel={t('EditControllerModal.submitLabel')}
      contentClassName="sm:max-w-[500px]"
    >
      {(form) => (
        <>
          <div className="flex items-center gap-2 text-sm font-medium">
            <Server className="h-4 w-4" />
            {t('EditControllerModal.sectionHeading')}
          </div>

          <FormField
            control={form.control}
            name="name"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('EditControllerModal.fields.name')}</FormLabel>
                <FormControl>
                  <Input {...field} />
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
                <FormLabel>{t('EditControllerModal.fields.description')}</FormLabel>
                <FormControl>
                  <Textarea placeholder={t('EditControllerModal.placeholders.description')} rows={2} {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormItem>
            <FormLabel>{t('EditControllerModal.fields.site')}</FormLabel>
            <Input value={siteName} disabled className="bg-muted" />
            <FormDescription>{t('EditControllerModal.descriptions.siteImmutable')}</FormDescription>
          </FormItem>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
            <div className="col-span-2">
              <FormField
                control={form.control}
                name="host"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('EditControllerModal.fields.host')}</FormLabel>
                    <FormControl>
                      <Input {...field} />
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
                  <FormLabel>{t('EditControllerModal.fields.port')}</FormLabel>
                  <FormControl>
                    <Input type="number" min={1} max={65535} {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>

          <FormField
            control={form.control}
            name="use_ssl"
            render={({ field }) => (
              <FormItem className="flex items-center justify-between space-y-0">
                <div className="space-y-0.5">
                  <FormLabel>{t('EditControllerModal.fields.useSsl')}</FormLabel>
                  <FormDescription>{t('EditControllerModal.descriptions.useSsl')}</FormDescription>
                </div>
                <FormControl>
                  <Switch checked={field.value} onCheckedChange={field.onChange} />
                </FormControl>
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="verify_ssl"
            render={({ field }) => (
              <FormItem className="flex items-center justify-between space-y-0">
                <div className="space-y-0.5">
                  <FormLabel>{t('EditControllerModal.fields.verifySsl')}</FormLabel>
                  <FormDescription>{t('EditControllerModal.descriptions.verifySsl')}</FormDescription>
                </div>
                <FormControl>
                  <Switch checked={field.value} onCheckedChange={field.onChange} />
                </FormControl>
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="sync_enabled"
            render={({ field }) => (
              <FormItem className="flex items-center justify-between space-y-0">
                <div className="space-y-0.5">
                  <FormLabel>{t('EditControllerModal.fields.syncEnabled')}</FormLabel>
                  <FormDescription>{t('EditControllerModal.descriptions.syncEnabled')}</FormDescription>
                </div>
                <FormControl>
                  <Switch checked={field.value} onCheckedChange={field.onChange} />
                </FormControl>
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="sync_interval_seconds"
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('EditControllerModal.fields.syncInterval')}</FormLabel>
                <FormControl>
                  <Input type="number" min={60} {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="is_active"
            render={({ field }) => (
              <FormItem className="flex items-center justify-between space-y-0">
                <div className="space-y-0.5">
                  <FormLabel>{t('EditControllerModal.fields.isActive')}</FormLabel>
                  <FormDescription>{t('EditControllerModal.descriptions.isActive')}</FormDescription>
                </div>
                <FormControl>
                  <Switch checked={field.value} onCheckedChange={field.onChange} />
                </FormControl>
              </FormItem>
            )}
          />
        </>
      )}
    </FormDialog>
  );
}
