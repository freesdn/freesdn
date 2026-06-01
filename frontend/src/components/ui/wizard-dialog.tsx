// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * WizardDialog · multi-step form dialog primitive.
 *
 * Built on react-hook-form + zod, sibling to FormDialog. Use when a dialog
 * needs Back/Next navigation across distinct steps with per-step validation.
 *
 * Each step:
 *  - Has a unique `id` and `label` (shown in the stepper)
 *  - Declares the `fields` it owns from the combined schema (used for per-step
 *    validation when "Next" is clicked · validates ONLY those fields, not the
 *    full schema, so optional later-step fields don't block early progress)
 *  - Renders its own JSX via `content(form)` render-prop
 *  - Optionally has a `validate(values)` async function for cross-field /
 *    server-side / async validation that should block "Next" (e.g. test
 *    connection, probe sites). If it returns a string, that becomes a
 *    server-error banner shown in the step.
 *
 * The full combined schema (`schema` prop) is validated on final submit.
 *
 * Behavior:
 *  - Stepper UI at top with current step highlighted, completed steps green
 *  - Back button on steps 2+
 *  - Next button on steps 1..N-1 (disabled while validating)
 *  - Submit button on step N (with destructive variant if `destructive`)
 *  - Server-error banner at footer (catches submit errors)
 *  - Form reset on dialog close
 *  - Click-outside blocked while a step is validating or submitting
 *
 * Usage:
 *
 *   const schema = z.object({
 *     // step 1
 *     type: z.enum(['slack', 'webhook']),
 *     // step 2
 *     name: z.string().min(1),
 *     url: z.string().url(),
 *     // step 3
 *     enabled: z.boolean(),
 *   });
 *
 *   <WizardDialog
 *     open={open}
 *     onOpenChange={setOpen}
 *     title="New integration"
 *     schema={schema}
 *     defaultValues={{ type: 'slack', name: '', url: '', enabled: true }}
 *     steps={[
 *       { id: 'choose',  label: 'Choose type', fields: ['type'],          content: (f) => <ChooseStep form={f} /> },
 *       { id: 'config',  label: 'Configure',   fields: ['name', 'url'],   content: (f) => <ConfigStep form={f} /> },
 *       { id: 'review',  label: 'Review',      fields: ['enabled'],       content: (f) => <ReviewStep form={f} /> },
 *     ]}
 *     onSubmit={async (values) => { await api.create(values); }}
 *     submitLabel="Create"
 *   />
 */
import { useCallback, useEffect, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import {
  useForm,
  type DefaultValues,
  type UseFormReturn,
  type FieldValues,
  type Path,
} from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import type { ZodType } from 'zod';
import { Loader2, AlertCircle, ChevronLeft, ChevronRight, Check } from 'lucide-react';
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

export interface WizardStep<T extends FieldValues> {
  /** Stable id used in the stepper + as React key */
  id: string;
  /** Human-readable label shown in the stepper */
  label: string;
  /**
   * Schema fields owned by this step. Used for per-step validation when
   * "Next" is clicked · validates ONLY these fields, so optional later-step
   * fields don't block progress. Pass `[]` if the step has no form fields
   * (e.g. a review-only step or async-only step).
   */
  fields: ReadonlyArray<Path<T>>;
  /**
   * Render the step's JSX. Receives the full form instance so the step can
   * use `form.control`, `form.watch()`, `form.setValue()`, etc.
   */
  content: (form: UseFormReturn<T>) => ReactNode;
  /**
   * Optional async validation. Called AFTER the step's own zod validation
   * passes. Return a string to block advancement and show that as the
   * step's error banner. Return undefined / null / void to allow advance.
   *
   * Use for: test-connection, probe-sites, server-side uniqueness checks.
   */
  validate?: (values: T) => Promise<string | null | undefined | void>;
}

export interface WizardDialogProps<T extends FieldValues> {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: string;
  /** Combined zod schema across all steps */
  schema: ZodType<T>;
  defaultValues: DefaultValues<T>;
  steps: ReadonlyArray<WizardStep<T>>;
  /** Final submit handler · called with all values from all steps */
  onSubmit: (values: T, form: UseFormReturn<T>) => Promise<void> | void;
  /** Submit button label on the final step. Default "Create". */
  submitLabel?: string;
  /** Treat submit as destructive (red button). Default false. */
  destructive?: boolean;
  /** Cancel button label. Default "Cancel". */
  cancelLabel?: string;
  /** Override dialog content className (default sm:max-w-[600px]) */
  contentClassName?: string;
  /**
   * Optional render-prop for a post-submit success view. When provided AND
   * onSubmit succeeds, the wizard transitions to a final "success" pane
   * instead of closing immediately. The user clicks the close button (or
   * triggers `onOpenChange(false)`) to dismiss.
   *
   * Use for: "Integration created · send a test event to verify" patterns
   * where the user needs to interact with the just-created resource before
   * leaving the dialog.
   *
   * The render-prop receives the submitted values and a `close` helper.
   */
  successContent?: (values: T, helpers: { close: () => void }) => ReactNode;
  /** Label for the close button on the success view. Default "Done". */
  successCloseLabel?: string;
}

export function WizardDialog<T extends FieldValues>({
  open,
  onOpenChange,
  title,
  description,
  schema,
  defaultValues,
  steps,
  onSubmit,
  submitLabel,
  destructive = false,
  cancelLabel,
  contentClassName,
  successContent,
  successCloseLabel,
}: WizardDialogProps<T>) {
  const { t } = useTranslation('common');
  const submitLabelText = submitLabel ?? t('WizardDialog.actions.create');
  const cancelLabelText = cancelLabel ?? t('WizardDialog.actions.cancel');
  const successCloseLabelText = successCloseLabel ?? t('WizardDialog.actions.done');
  const [stepIndex, setStepIndex] = useState(0);
  const [stepError, setStepError] = useState<string | null>(null);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isAdvancing, setIsAdvancing] = useState(false);
  const [submittedValues, setSubmittedValues] = useState<T | null>(null);

  const form = useForm<T>({
    resolver: zodResolver(schema as never) as never,
    defaultValues,
    mode: 'onSubmit',
    // Critical for wizards: keep field values when steps unmount/remount.
    // Without this, advancing to step 2 would discard step 1's values.
    shouldUnregister: false,
  });

  // Reset on every open · supports the "switch from create to edit" use case
  useEffect(() => {
    if (open) {
      form.reset(defaultValues);
      setStepIndex(0);
      setStepError(null);
      setSubmitError(null);
      setSubmittedValues(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const currentStep = steps[stepIndex];
  const isFirstStep = stepIndex === 0;
  const isLastStep = stepIndex === steps.length - 1;

  const handleNext = useCallback(async () => {
    if (!currentStep) return;
    setStepError(null);

    // 1. Validate ONLY the current step's fields
    const isValid = currentStep.fields.length === 0
      ? true
      : await form.trigger(currentStep.fields as Path<T>[]);
    if (!isValid) return;

    // 2. Run optional async validate hook
    if (currentStep.validate) {
      setIsAdvancing(true);
      try {
        const err = await currentStep.validate(form.getValues());
        if (err) {
          setStepError(err);
          return;
        }
      } catch (err) {
        setStepError(extractErrorMessage(err, t));
        return;
      } finally {
        setIsAdvancing(false);
      }
    }

    // 3. Advance
    setStepIndex((i) => Math.min(i + 1, steps.length - 1));
  }, [currentStep, form, steps.length]);

  const handleBack = useCallback(() => {
    setStepError(null);
    setStepIndex((i) => Math.max(i - 1, 0));
  }, []);

  const handleSubmit = form.handleSubmit(async (values) => {
    setSubmitError(null);
    try {
      await onSubmit(values, form);
      // If a successContent render-prop was provided, transition to the
      // success pane instead of closing. Otherwise the parent's onSubmit
      // typically calls onOpenChange(false) on its own.
      if (successContent) {
        setSubmittedValues(values);
      }
    } catch (err) {
      setSubmitError(extractErrorMessage(err, t));
    }
  });

  const isSubmitting = form.formState.isSubmitting;
  const lockedDuringWork = isAdvancing || isSubmitting;

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next && lockedDuringWork) return;
        onOpenChange(next);
      }}
    >
      <DialogContent className={cn('sm:max-w-[600px]', contentClassName)}>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>

        {/* Success view · replaces wizard chrome after successful submit */}
        {submittedValues && successContent ? (
          <>
            <div className="min-h-[160px]">
              {successContent(submittedValues, { close: () => onOpenChange(false) })}
            </div>
            <DialogFooter>
              <Button type="button" onClick={() => onOpenChange(false)}>
                {successCloseLabelText}
              </Button>
            </DialogFooter>
          </>
        ) : (
          <>

        {/* Stepper */}
        <Stepper steps={steps} currentIndex={stepIndex} />

        <Form {...form}>
          <form
            onSubmit={(e) => {
              // Always preventDefault · we drive submission via button onClick.
              // This catches Enter-key-in-input on early steps too.
              e.preventDefault();
              if (!isLastStep) {
                void handleNext();
              } else {
                void handleSubmit();
              }
            }}
            className="space-y-4"
          >
            {/* Step content · render ALL steps, hide inactive ones via CSS.
                This keeps every FormField mounted so RHF preserves field
                values across step navigation. Toggling display:none doesn't
                unmount the React tree, just hides it visually. */}
            <div className="min-h-[160px]">
              {steps.map((step, i) => (
                <div key={step.id} hidden={i !== stepIndex} aria-hidden={i !== stepIndex}>
                  {step.content(form)}
                </div>
              ))}
            </div>

            {/* Step-level error (from async validate hook) */}
            {stepError && (
              <ErrorBanner message={stepError} />
            )}

            {/* Final submit error */}
            {submitError && isLastStep && (
              <ErrorBanner message={submitError} />
            )}

            <DialogFooter className="gap-2 sm:gap-2">
              {!isFirstStep && (
                <Button
                  type="button"
                  variant="ghost"
                  onClick={handleBack}
                  disabled={lockedDuringWork}
                  className="mr-auto"
                >
                  <ChevronLeft className="h-4 w-4 mr-1" />
                  {t('WizardDialog.actions.back')}
                </Button>
              )}

              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
                disabled={lockedDuringWork}
              >
                {cancelLabelText}
              </Button>

              {!isLastStep ? (
                <Button
                  type="button"
                  onClick={handleNext}
                  disabled={lockedDuringWork}
                >
                  {isAdvancing && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                  {t('WizardDialog.actions.next')}
                  <ChevronRight className="h-4 w-4 ml-1" />
                </Button>
              ) : (
                <Button
                  type="button"
                  onClick={() => void handleSubmit()}
                  variant={destructive ? 'destructive' : 'default'}
                  disabled={lockedDuringWork}
                >
                  {isSubmitting && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                  {submitLabelText}
                </Button>
              )}
            </DialogFooter>
          </form>
        </Form>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

// ── Internal stepper UI ────────────────────────────────────────────────────

interface StepperProps<T extends FieldValues> {
  steps: ReadonlyArray<WizardStep<T>>;
  currentIndex: number;
}

function Stepper<T extends FieldValues>({ steps, currentIndex }: StepperProps<T>) {
  const { t } = useTranslation('common');
  return (
    <div className="flex items-center gap-2 py-2" role="list" aria-label={t('WizardDialog.ariaLabel.steps')}>
      {steps.map((step, i) => {
        const isCompleted = i < currentIndex;
        const isActive = i === currentIndex;
        const isFuture = i > currentIndex;

        return (
          <div
            key={step.id}
            role="listitem"
            aria-current={isActive ? 'step' : undefined}
            className="flex items-center gap-2 flex-1 min-w-0"
          >
            <div
              className={cn(
                'flex h-7 w-7 items-center justify-center rounded-full text-xs font-semibold flex-shrink-0 transition-colors',
                isCompleted && 'bg-success text-success-foreground',
                isActive && 'bg-primary text-primary-foreground',
                isFuture && 'bg-muted text-muted-foreground',
              )}
            >
              {isCompleted ? <Check className="h-3.5 w-3.5" /> : i + 1}
            </div>
            <span
              className={cn(
                'text-xs font-medium truncate',
                isActive && 'text-foreground',
                !isActive && 'text-muted-foreground',
              )}
            >
              {step.label}
            </span>
            {i < steps.length - 1 && (
              <div
                aria-hidden
                className={cn(
                  'flex-1 h-px min-w-2',
                  isCompleted ? 'bg-success' : 'bg-border',
                )}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── Helpers ────────────────────────────────────────────────────────────────

function ErrorBanner({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm">
      <AlertCircle className="h-4 w-4 text-destructive flex-shrink-0 mt-0.5" />
      <p className="text-destructive">{message}</p>
    </div>
  );
}

function extractErrorMessage(err: unknown, t: (key: string) => string): string {
  if (!err) return t('WizardDialog.errors.unexpected');
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
