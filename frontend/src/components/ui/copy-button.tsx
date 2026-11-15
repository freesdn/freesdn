// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * A copy button that tells the truth.
 *
 *   <CopyButton value={apiKey} />                       // icon only
 *   <CopyButton value={command} label={t('copyCommand')} />
 *
 * It says "Copied" only after the clipboard accepted the text, and "Copy
 * failed" (with a hint to select and copy by hand) when it did not, for
 * example on a plain-HTTP origin where the browser offers no clipboard
 * access or when permission is refused. The result is also announced to
 * screen readers.
 */
import { Check, Copy, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Button, type ButtonProps } from './button';
import { useCopyToClipboard } from '@/hooks/useCopyToClipboard';
import { cn } from '../../lib/utils';

export interface CopyButtonProps extends Omit<ButtonProps, 'onClick' | 'value' | 'children'> {
  /** The text to copy. */
  value: string;
  /** Visible label. Without one the button is icon-only (with an accessible name). */
  label?: string;
  /** Called with the result after each attempt. */
  onCopyResult?: (copied: boolean) => void;
}

export function CopyButton({
  value,
  label,
  onCopyResult,
  variant = 'ghost',
  size,
  className,
  'aria-label': ariaLabel,
  ...props
}: CopyButtonProps) {
  const { t } = useTranslation('common');
  const { copy, state } = useCopyToClipboard();

  const idleName = ariaLabel ?? label ?? t('CopyButton.copy');
  const name =
    state === 'copied' ? t('CopyButton.copied') : state === 'failed' ? t('CopyButton.failed') : idleName;
  const Icon = state === 'copied' ? Check : state === 'failed' ? X : Copy;

  return (
    <>
      <Button
        type="button"
        variant={variant}
        size={size ?? (label ? 'sm' : 'icon')}
        className={cn(
          !label && 'h-8 w-8',
          state === 'copied' && 'text-success',
          state === 'failed' && 'text-destructive',
          className,
        )}
        aria-label={label ? undefined : name}
        title={state === 'failed' ? t('CopyButton.failedHint') : name}
        data-copy-state={state}
        onClick={async (e) => {
          e.stopPropagation();
          const ok = await copy(value);
          onCopyResult?.(ok);
        }}
        {...props}
      >
        <Icon className={cn('h-4 w-4', label && 'mr-1.5')} aria-hidden="true" />
        {label && (state === 'idle' ? label : name)}
      </Button>
      <span className="sr-only" role="status" aria-live="polite">
        {state === 'copied'
          ? t('CopyButton.copied')
          : state === 'failed'
            ? t('CopyButton.failedHint')
            : ''}
      </span>
    </>
  );
}
