// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FormDialog · unified create/edit dialog primitive.
 *
 * Wraps shadcn Dialog + react-hook-form + zod with conventions for:
 *   - submit button + loading state
 *   - cancel button that resets the form
 *   - server-error banner above the footer
 *   - automatic form reset on dialog close
 *   - keyboard submit (Enter inside any field)
 *
 * Replaces ~40 ad-hoc dialogs across the app, each of which currently
 * rolls its own validation + submit + error display.
 *
 * Usage:
 *
 *   const schema = z.object({
 *     name: z.string().min(1, 'Required'),
 *     port: z.coerce.number().int().positive(),
 *   });
 *
 *   <FormDialog
 *     open={open}
 *     onOpenChange={setOpen}
 *     title="Add controller"
 *     schema={schema}
 *     defaultValues={{ name: '', port: 443 }}
 *     onSubmit={async (values) => { await api.create(values); }}
 *     submitLabel="Create"
 *   >
 *     {(form) => (
 *       <>
 *         <FormField name="name" control={form.control} render={...} />
 *         <FormField name="port" control={form.control} render={...} />
 *       </>
 *     )}
 *   </FormDialog>
 */
import { useEffect, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useForm, type DefaultValues, type UseFormReturn, type FieldValues } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import type { ZodType } from 'zod';
import { Loader2, AlertCircle } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from './dialog';
import { Button } from './button';
import { Form } from './form';
import { cn } from '../../lib/utils';

export interface FormDialogProps<T extends FieldValues> {
  /** Controlled open state */
  open: boolean;
  /** Open/close callback */
  onOpenChange: (open: boolean) => void;
  /** Dialog title */
  title: string;
  /** Optional dialog description */
  description?: string;
  /** zod schema used for validation. Form values are inferred from this. */
  schema: ZodType<T>;
  /** Initial values (also used for `Reset` semantics on close) */
  defaultValues: DefaultValues<T>;
  /**
   * Submit handler. Receives validated values + the form instance (so you can
   * call form.setError on server-side validation failures, for example).
   * Throw or reject to surface a generic server error in the banner.
   */
  onSubmit: (values: T, form: UseFormReturn<T>) => Promise<void> | void;
  /**
   * Render-prop for the form fields. Receives the form instance so you can
   * pass `form.control` to `<FormField>` and call `form.watch()` etc.
   */
  children: (form: UseFormReturn<T>) => ReactNode;
  /** Submit button label. Default: "Save". */
  submitLabel?: string;
  /** Cancel button label. Default: "Cancel". */
  cancelLabel?: string;
  /** Treat submit as destructive (red button, e.g. for "Delete") */
  destructive?: boolean;
  /** Disable the submit button (useful when fields are loading from API) */
  submitDisabled?: boolean;
  /** Override the dialog content className (e.g. `sm:max-w-[600px]`) */
  contentClassName?: string;
  /** Optional element to render to the left of the submit button (e.g. a "Reset to default" link) */
  footerExtra?: ReactNode;
}

export function FormDialog<T extends FieldValues>({
  open,
  onOpenChange,
  title,
  description,
  schema,
  defaultValues,
  onSubmit,
  children,
  submitLabel,
  cancelLabel,
  destructive = false,
  submitDisabled = false,
  contentClassName,
  footerExtra,
}: FormDialogProps<T>) {
  const { t } = useTranslation('common');
  // Default the button labels to the localized common strings. Callers can
  // still override via the submitLabel/cancelLabel props.
  const resolvedSubmitLabel = submitLabel ?? t('save');
  const resolvedCancelLabel = cancelLabel ?? t('cancel');
  const form = useForm<T>({
    // Cast: zod's resolver type is invariant on T but we know it's the same shape
    // because both come from `schema: ZodType<T>`.
    resolver: zodResolver(schema as never) as never,
    defaultValues,
    mode: 'onSubmit',
  });

  const [serverError, setServerError] = useState<string | null>(null);

  // Reset the form whenever the dialog opens (defaultValues may have changed
  // · e.g. switching from "create" to "edit existing row" reuses the same dialog)
  useEffect(() => {
    if (open) {
      form.reset(defaultValues);
      setServerError(null);
    }
    // We intentionally only run this on `open` · defaultValues identity changes
    // every render in many call-sites, and we don't want to wipe in-progress edits.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const handleSubmit = form.handleSubmit(async (values) => {
    setServerError(null);
    try {
      await onSubmit(values, form);
    } catch (err) {
      setServerError(extractErrorMessage(err));
    }
  });

  const isSubmitting = form.formState.isSubmitting;

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        // Block close while a submit is in flight to avoid orphaned mutations
        if (!next && isSubmitting) return;
        onOpenChange(next);
      }}
    >
      <DialogContent className={cn('sm:max-w-[480px]', contentClassName)}>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-4">{children(form)}</div>

            {serverError && (
              <div className="flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm">
                <AlertCircle className="h-4 w-4 text-destructive flex-shrink-0 mt-0.5" />
                <p className="text-destructive">{serverError}</p>
              </div>
            )}

            <DialogFooter className="gap-2 sm:gap-2">
              {footerExtra}
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
                disabled={isSubmitting}
              >
                {resolvedCancelLabel}
              </Button>
              <Button
                type="submit"
                variant={destructive ? 'destructive' : 'default'}
                disabled={isSubmitting || submitDisabled}
              >
                {isSubmitting && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                {resolvedSubmitLabel}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}

/** Extract a human-readable error message from anything thrown during submit. */
function extractErrorMessage(err: unknown): string {
  if (!err) return 'An unexpected error occurred';
  // Axios-style error
  if (typeof err === 'object' && err !== null && 'response' in err) {
    const r = (err as { response?: { data?: { detail?: unknown; message?: unknown } } }).response;
    const detail = r?.data?.detail;
    if (typeof detail === 'string') return detail;
    const message = r?.data?.message;
    if (typeof message === 'string') return message;
  }
  if (err instanceof Error) return err.message;
  return String(err);
}
