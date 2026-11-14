// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Syslog severity pills for the Collector and Log Explorer pages.
 *
 * The pages used to keep two copies of a solid Tailwind palette with white
 * text (red-400, blue-400, gray-400 and so on, about 2.5 to 2.8:1, below WCAG
 * AA) and an un-tokenized light-grey fallback. The pills now use the theme
 * tokens in a way that holds AA in both themes, which `severity.test.ts`
 * checks against the token values in index.css:
 *
 * - emergency and alert: a solid destructive fill with its foreground
 *   (the destructive token is the one fill that carries its foreground at AA);
 * - every other level: the label in the foreground colour on a 15% tint of
 *   its tone, with a solid dot of the tone. Coloured text on a tint fails AA
 *   for every tone in at least one theme, so the colour is carried by the
 *   tint, border and dot, and the label stays readable.
 */
import { useTranslation } from 'react-i18next';
import { cn } from '@/lib/utils';

export type SeverityTone = 'destructive' | 'warning' | 'info' | 'neutral';

export interface SeverityStyle {
  tone: SeverityTone;
  /** Solid fill (the most urgent levels) instead of a tint. */
  solid: boolean;
}

/** Every value `CollectorLog.severity` can hold, plus the `info` shorthand. */
export const SEVERITY_STYLES: Record<string, SeverityStyle> = {
  emergency: { tone: 'destructive', solid: true },
  alert: { tone: 'destructive', solid: true },
  critical: { tone: 'destructive', solid: false },
  error: { tone: 'destructive', solid: false },
  warning: { tone: 'warning', solid: false },
  notice: { tone: 'info', solid: false },
  // Both spellings on purpose. The receivers store the RFC 5424 name
  // ('informational', SEVERITY_NAMES in
  // backend/app/modules/collector/services/syslog.py), while the filter
  // dropdown, the API description and every syslog shorthand say 'info'.
  informational: { tone: 'info', solid: false },
  info: { tone: 'info', solid: false },
  debug: { tone: 'neutral', solid: false },
};

/** Class names per style; the contrast test reads the same table. */
export const PILL_CLASSES: Record<SeverityTone | 'destructive-solid', string> = {
  'destructive-solid': 'border-transparent bg-destructive text-destructive-foreground font-semibold',
  destructive: 'border-destructive/50 bg-destructive/15 text-foreground',
  warning: 'border-warning/50 bg-warning/15 text-foreground',
  info: 'border-info/50 bg-info/15 text-foreground',
  neutral: 'border-border bg-transparent text-foreground',
};

const DOT_CLASSES: Record<SeverityTone, string> = {
  destructive: 'bg-destructive',
  warning: 'bg-warning',
  info: 'bg-info',
  neutral: 'bg-muted-foreground',
};

const LABEL_KEYS: Record<string, string> = {
  emergency: 'emergency',
  alert: 'alert',
  critical: 'critical',
  error: 'error',
  warning: 'warning',
  notice: 'notice',
  informational: 'info',
  info: 'info',
  debug: 'debug',
};

export function severityStyle(severity: string): SeverityStyle | undefined {
  return SEVERITY_STYLES[severity.toLowerCase()];
}

export function SeverityBadge({ severity }: { severity: string | null }) {
  const { t } = useTranslation('collector');
  if (!severity) {
    return (
      <span className="inline-flex items-center rounded border border-border px-1.5 py-0.5 text-xs text-muted-foreground">
        -
      </span>
    );
  }
  const key = severity.toLowerCase();
  const style = SEVERITY_STYLES[key];
  const labelKey = LABEL_KEYS[key];
  const label = labelKey ? t(`LogExplorerPage.severity.${labelKey}`) : severity;
  const pill = style
    ? PILL_CLASSES[style.solid && style.tone === 'destructive' ? 'destructive-solid' : style.tone]
    : PILL_CLASSES.neutral;
  return (
    <span
      data-severity={key}
      className={cn('inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-xs font-medium', pill)}
    >
      {style && !style.solid && (
        <span aria-hidden="true" className={cn('h-1.5 w-1.5 shrink-0 rounded-full', DOT_CLASSES[style.tone])} />
      )}
      {label}
    </span>
  );
}
