// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Delete Controller Dialog
 *
 * Built on the canonical FormDialog primitive: zod handles "type the name to
 * confirm", react-hook-form handles loading/error state, the FormDialog wrapper
 * handles the destructive button + server-error banner.
 */

import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { z } from 'zod';
import { AlertTriangle } from 'lucide-react';
import { FormDialog } from '@/components/ui/form-dialog';
import { FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { controllersApi } from '@/lib/api';

interface Controller {
  id: string;
  name: string;
  device_count?: number;
}

interface DeleteControllerDialogProps {
  controller: Controller | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess?: () => void;
}

export function DeleteControllerDialog({
  controller,
  open,
  onOpenChange,
  onSuccess,
}: DeleteControllerDialogProps) {
  const { t } = useTranslation('common');
  const queryClient = useQueryClient();

  const deleteMutation = useMutation({
    mutationFn: (id: string) => controllersApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['controllers'] });
      onOpenChange(false);
      onSuccess?.();
    },
  });

  if (!controller) return null;

  const hasDevices = (controller.device_count || 0) > 0;
  const expectedName = controller.name;

  // Zod refinement gives us native validation for "type the name to confirm".
  const schema = z.object({
    confirmation: z
      .string()
      .refine((v) => v === expectedName, {
        message: t('DeleteControllerDialog.validation.nameMismatch'),
      }),
  });

  return (
    <FormDialog
      open={open}
      onOpenChange={onOpenChange}
      title={t('DeleteControllerDialog.title')}
      schema={schema}
      defaultValues={{ confirmation: '' }}
      submitLabel={t('DeleteControllerDialog.submitLabel')}
      destructive
      onSubmit={async () => {
        await deleteMutation.mutateAsync(controller.id);
      }}
    >
      {(form) => (
        <div className="space-y-3">
          <div className="flex items-start gap-2 text-sm">
            <AlertTriangle className="h-4 w-4 text-destructive flex-shrink-0 mt-0.5" />
            <p>
              {t('DeleteControllerDialog.confirmPrompt.before')}
              <strong>{controller.name}</strong>
              {t('DeleteControllerDialog.confirmPrompt.after')}
            </p>
          </div>

          {hasDevices && (
            <div className="rounded-md bg-warning/10 border border-warning/20 p-3 text-sm text-warning">
              <strong>{t('DeleteControllerDialog.warning.label')}</strong>{' '}
              {t('DeleteControllerDialog.warning.message', { count: controller.device_count })}
            </div>
          )}

          <FormField
            control={form.control}
            name="confirmation"
            render={({ field }) => (
              <FormItem>
                <FormLabel>
                  {t('DeleteControllerDialog.confirmLabel.before')}
                  <strong>{controller.name}</strong>
                  {t('DeleteControllerDialog.confirmLabel.after')}
                </FormLabel>
                <FormControl>
                  <Input placeholder={controller.name} autoFocus {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>
      )}
    </FormDialog>
  );
}
