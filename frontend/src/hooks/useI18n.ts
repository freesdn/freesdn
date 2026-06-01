// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * i18n Hook for FreeSDN
 * =======================
 * 
 * Custom hook that wraps react-i18next with additional functionality:
 * - Type-safe translation keys (when combined with TypeScript)
 * - Locale info helpers
 * - Formatted date/time/number utilities
 */

import { useTranslation as useI18NextTranslation } from 'react-i18next';
import { useCallback, useMemo } from 'react';
import {
  SUPPORTED_LOCALES,
  getCurrentLanguage,
  changeLanguage,
  isRTL,
  type TranslationNamespace,
} from '@/lib/i18n';

/**
 * Enhanced translation hook with additional utilities
 */
export function useI18n(namespace?: TranslationNamespace | TranslationNamespace[]) {
  const { t, i18n, ready } = useI18NextTranslation(namespace);
  
  const currentLocale = getCurrentLanguage();
  const localeInfo = useMemo(
    () => SUPPORTED_LOCALES.find((l) => l.code === currentLocale) || SUPPORTED_LOCALES[0],
    [currentLocale]
  );

  /**
   * Format a number according to the current locale
   */
  const formatNumber = useCallback(
    (value: number, options?: Intl.NumberFormatOptions) => {
      return new Intl.NumberFormat(currentLocale, options).format(value);
    },
    [currentLocale]
  );

  /**
   * Format currency according to the current locale
   */
  const formatCurrency = useCallback(
    (value: number, currency: string = 'USD') => {
      return new Intl.NumberFormat(currentLocale, {
        style: 'currency',
        currency,
      }).format(value);
    },
    [currentLocale]
  );

  /**
   * Format a date according to the current locale
   */
  const formatDate = useCallback(
    (date: Date | string | number, options?: Intl.DateTimeFormatOptions) => {
      const d = date instanceof Date ? date : new Date(date);
      return new Intl.DateTimeFormat(currentLocale, options).format(d);
    },
    [currentLocale]
  );

  /**
   * Format a date with time
   */
  const formatDateTime = useCallback(
    (date: Date | string | number, options?: Intl.DateTimeFormatOptions) => {
      const d = date instanceof Date ? date : new Date(date);
      return new Intl.DateTimeFormat(currentLocale, {
        dateStyle: 'medium',
        timeStyle: 'short',
        ...options,
      }).format(d);
    },
    [currentLocale]
  );

  /**
   * Format time only
   */
  const formatTime = useCallback(
    (date: Date | string | number, options?: Intl.DateTimeFormatOptions) => {
      const d = date instanceof Date ? date : new Date(date);
      return new Intl.DateTimeFormat(currentLocale, {
        timeStyle: 'short',
        ...options,
      }).format(d);
    },
    [currentLocale]
  );

  /**
   * Format relative time (e.g., "2 hours ago")
   */
  const formatRelativeTime = useCallback(
    (date: Date | string | number) => {
      const d = date instanceof Date ? date : new Date(date);
      const now = new Date();
      const diffInSeconds = Math.floor((now.getTime() - d.getTime()) / 1000);

      const rtf = new Intl.RelativeTimeFormat(currentLocale, { numeric: 'auto' });

      if (diffInSeconds < 60) {
        return rtf.format(-diffInSeconds, 'second');
      }
      if (diffInSeconds < 3600) {
        return rtf.format(-Math.floor(diffInSeconds / 60), 'minute');
      }
      if (diffInSeconds < 86400) {
        return rtf.format(-Math.floor(diffInSeconds / 3600), 'hour');
      }
      if (diffInSeconds < 2592000) {
        return rtf.format(-Math.floor(diffInSeconds / 86400), 'day');
      }
      if (diffInSeconds < 31536000) {
        return rtf.format(-Math.floor(diffInSeconds / 2592000), 'month');
      }
      return rtf.format(-Math.floor(diffInSeconds / 31536000), 'year');
    },
    [currentLocale]
  );

  /**
   * Format a list of items
   */
  const formatList = useCallback(
    (items: string[], type: 'conjunction' | 'disjunction' = 'conjunction') => {
      // Use ListFormat if available, otherwise fallback to join
      if ('ListFormat' in Intl) {
        return new (Intl as unknown as { ListFormat: new (locale: string, options: { type: string }) => { format(items: string[]): string } }).ListFormat(currentLocale, { type }).format(items);
      }
      return items.join(type === 'disjunction' ? ' or ' : ', ');
    },
    [currentLocale]
  );

  /**
   * Format bytes to human readable
   */
  const formatBytes = useCallback(
    (bytes: number, decimals: number = 2) => {
      if (bytes === 0) return '0 B';

      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));

      return `${formatNumber(parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)))} ${sizes[i]}`;
    },
    [formatNumber]
  );

  /**
   * Format duration in seconds to human readable
   */
  const formatDuration = useCallback(
    (seconds: number) => {
      if (seconds < 60) {
        return t('common:time.seconds', { count: Math.floor(seconds) });
      }
      if (seconds < 3600) {
        return t('common:time.minutes', { count: Math.floor(seconds / 60) });
      }
      if (seconds < 86400) {
        return t('common:time.hours', { count: Math.floor(seconds / 3600) });
      }
      return t('common:time.days', { count: Math.floor(seconds / 86400) });
    },
    [t]
  );

  return {
    // Base i18next
    t,
    i18n,
    ready,
    
    // Locale info
    locale: currentLocale,
    localeInfo,
    isRTL: isRTL(currentLocale),
    supportedLocales: SUPPORTED_LOCALES,
    
    // Actions
    changeLanguage,
    
    // Formatters
    formatNumber,
    formatCurrency,
    formatDate,
    formatDateTime,
    formatTime,
    formatRelativeTime,
    formatList,
    formatBytes,
    formatDuration,
  };
}

/**
 * Re-export useTranslation for simple use cases
 */
export { useTranslation as useT } from 'react-i18next';

export default useI18n;
