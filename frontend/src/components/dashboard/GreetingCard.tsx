// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * GreetingCard
 * ==============
 *
 * Personalised welcome tile for the dashboard stat row. Shows a time-of-day
 * greeting (Good morning / afternoon / evening / night), the user's first
 * name, and today's date. Visual rhythm matches the surrounding StatCards
 * so it slots into the same `lg:grid-cols-4` grid without breaking layout.
 *
 * The icon and accent color shift with time of day to give the dashboard a
 * subtle "this is YOUR workspace right now" feel · sunrise → sun → sunset →
 * moon as the day progresses.
 */

import { motion } from 'framer-motion';
import { Sunrise, Sun, Sunset, Moon, type LucideIcon } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { cn } from '@/lib/utils';

interface GreetingCardProps {
  /** First name (or display name fallback). Renders without name if blank. */
  name?: string | null;
  /** Override the date string · used by tests; defaults to today. */
  dateOverride?: Date;
  className?: string;
}

interface Greeting {
  /** English fallback text · kept for the exported pure helper / non-i18n callers */
  text: string;
  /** Semantic i18n key suffix · translated at the render site via t() */
  key: string;
  icon: LucideIcon;
  /** bg / icon-color / ring tone classes · matches StatCard variants */
  iconBg: string;
  iconColor: string;
  iconRing: string;
}

/**
 * Pure helper: pick a greeting based on local hour.
 * Exposed for unit tests so we don't need to mock Date.
 */
export function getGreeting(date: Date = new Date()): Greeting {
  const h = date.getHours();
  if (h >= 5 && h < 12) {
    return {
      text: 'Good morning',
      key: 'greetings.morning',
      icon: Sunrise,
      iconBg: 'bg-warning/10',
      iconColor: 'text-warning',
      iconRing: 'ring-warning/20',
    };
  }
  if (h >= 12 && h < 17) {
    return {
      text: 'Good afternoon',
      key: 'greetings.afternoon',
      icon: Sun,
      iconBg: 'bg-info/10',
      iconColor: 'text-info',
      iconRing: 'ring-info/20',
    };
  }
  if (h >= 17 && h < 22) {
    return {
      text: 'Good evening',
      key: 'greetings.evening',
      icon: Sunset,
      iconBg: 'bg-primary/10',
      iconColor: 'text-primary',
      iconRing: 'ring-primary/20',
    };
  }
  return {
    text: 'Working late',
    key: 'greetings.late',
    icon: Moon,
    iconBg: 'bg-muted',
    iconColor: 'text-muted-foreground',
    iconRing: 'ring-border',
  };
}

export function GreetingCard({ name, dateOverride, className }: GreetingCardProps) {
  const { t } = useTranslation('common');
  const date = dateOverride ?? new Date();
  const greeting = getGreeting(date);
  const Icon = greeting.icon;

  // Title combines greeting + name when available
  const greetingText = t(`GreetingCard.${greeting.key}`);
  const fullGreeting = name?.trim()
    ? t('GreetingCard.fullGreeting', { greeting: greetingText, name: name.trim() })
    : greetingText;
  const dateLabel = date.toLocaleDateString(undefined, {
    weekday: 'long',
    month: 'long',
    day: 'numeric',
  });

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className={cn(
        'relative overflow-hidden rounded-xl border bg-card p-4 sm:p-6 shadow-sm',
        className,
      )}
    >
      <div className="relative flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          {/* Greeting wraps to 2 lines if needed · NEVER truncate the user's name */}
          <motion.p
            className="text-lg sm:text-xl font-bold tracking-tight leading-tight break-words"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.1 }}
          >
            {fullGreeting}
          </motion.p>
          <p className="mt-2 text-xs text-muted-foreground">{dateLabel}</p>
        </div>

        <div
          className={cn(
            'flex h-10 w-10 sm:h-11 sm:w-11 items-center justify-center rounded-xl ring-1 flex-shrink-0',
            greeting.iconBg,
            greeting.iconRing,
          )}
        >
          <Icon className={cn('h-5 w-5', greeting.iconColor)} />
        </div>
      </div>
    </motion.div>
  );
}
