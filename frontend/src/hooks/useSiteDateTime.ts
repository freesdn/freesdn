// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Site DateTime Formatting Hook
 * ================================
 * 
 * Provides site-aware datetime formatting based on site settings:
 * - Timezone conversion
 * - Time format (12h/24h)
 * - Date format (various patterns)
 * 
 * Usage:
 *   const { formatSiteDate, formatSiteTime, formatSiteDateTime } = useSiteDateTime(site);
 */

import { useCallback, useMemo } from 'react';

export type TimeFormat = '12h' | '24h';

export type DateFormatPattern =
  | 'YYYY-MM-DD'
  | 'DD/MM/YYYY'
  | 'MM/DD/YYYY'
  | 'DD-MM-YYYY'
  | 'DD.MM.YYYY'
  | 'YYYY/MM/DD';

export interface SiteSettings {
  timezone?: string;
  time_format?: TimeFormat;
  date_format?: DateFormatPattern;
}

// Helper to manually format date according to pattern
function manualFormatDate(date: Date, pattern: DateFormatPattern): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');

  switch (pattern) {
    case 'YYYY-MM-DD':
      return `${year}-${month}-${day}`;
    case 'DD/MM/YYYY':
      return `${day}/${month}/${year}`;
    case 'MM/DD/YYYY':
      return `${month}/${day}/${year}`;
    case 'DD-MM-YYYY':
      return `${day}-${month}-${year}`;
    case 'DD.MM.YYYY':
      return `${day}.${month}.${year}`;
    case 'YYYY/MM/DD':
      return `${year}/${month}/${day}`;
    default:
      return `${year}-${month}-${day}`;
  }
}

// Helper to format time according to 12h/24h preference
function formatTimeValue(date: Date, timeFormat: TimeFormat): string {
  const hours = date.getHours();
  const minutes = String(date.getMinutes()).padStart(2, '0');

  if (timeFormat === '12h') {
    const period = hours >= 12 ? 'PM' : 'AM';
    const displayHours = hours % 12 || 12;
    return `${displayHours}:${minutes} ${period}`;
  }
  
  return `${String(hours).padStart(2, '0')}:${minutes}`;
}

/**
 * Convert a date to a specific timezone
 */
function toTimezone(date: Date, timezone: string): Date {
  try {
    // Get the date string in the target timezone
    const options: Intl.DateTimeFormatOptions = {
      timeZone: timezone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    };
    
    const formatter = new Intl.DateTimeFormat('en-US', options);
    const parts = formatter.formatToParts(date);
    
    const getPart = (type: Intl.DateTimeFormatPartTypes) =>
      parts.find(p => p.type === type)?.value || '0';
    
    // Create a new date from the parts
    const tzDate = new Date(
      parseInt(getPart('year')),
      parseInt(getPart('month')) - 1,
      parseInt(getPart('day')),
      parseInt(getPart('hour')),
      parseInt(getPart('minute')),
      parseInt(getPart('second'))
    );
    
    return tzDate;
  } catch {
    // Fallback to original date if timezone is invalid
    return date;
  }
}

/**
 * Hook for site-aware datetime formatting
 */
export function useSiteDateTime(site?: SiteSettings | null) {
  const timezone = site?.timezone || 'UTC';
  const timeFormat = site?.time_format || '24h';
  const dateFormat = site?.date_format || 'YYYY-MM-DD';

  /**
   * Convert date to site timezone
   */
  const toSiteTime = useCallback(
    (date: Date | string | number): Date => {
      const d = date instanceof Date ? date : new Date(date);
      return toTimezone(d, timezone);
    },
    [timezone]
  );

  /**
   * Format date according to site's date format preference
   */
  const formatSiteDate = useCallback(
    (date: Date | string | number): string => {
      const d = date instanceof Date ? date : new Date(date);
      const siteDate = toTimezone(d, timezone);
      return manualFormatDate(siteDate, dateFormat);
    },
    [timezone, dateFormat]
  );

  /**
   * Format time according to site's time format preference (12h/24h)
   */
  const formatSiteTime = useCallback(
    (date: Date | string | number, includeSeconds = false): string => {
      const d = date instanceof Date ? date : new Date(date);
      const siteDate = toTimezone(d, timezone);
      const base = formatTimeValue(siteDate, timeFormat);
      
      if (includeSeconds) {
        const seconds = String(siteDate.getSeconds()).padStart(2, '0');
        // Insert seconds before AM/PM for 12h format
        if (timeFormat === '12h') {
          return base.replace(/(\d+:\d+)( [AP]M)/, `$1:${seconds}$2`);
        }
        return `${base}:${seconds}`;
      }
      
      return base;
    },
    [timezone, timeFormat]
  );

  /**
   * Format full datetime according to site preferences
   */
  const formatSiteDateTime = useCallback(
    (date: Date | string | number, includeSeconds = false): string => {
      const dateStr = formatSiteDate(date);
      const timeStr = formatSiteTime(date, includeSeconds);
      return `${dateStr} ${timeStr}`;
    },
    [formatSiteDate, formatSiteTime]
  );

  /**
   * Format time with timezone abbreviation
   */
  const formatSiteTimeWithZone = useCallback(
    (date: Date | string | number): string => {
      const timeStr = formatSiteTime(date);
      
      try {
        // Get timezone abbreviation
        const d = date instanceof Date ? date : new Date(date);
        const formatter = new Intl.DateTimeFormat('en', {
          timeZone: timezone,
          timeZoneName: 'short',
        });
        const parts = formatter.formatToParts(d);
        const tzName = parts.find(p => p.type === 'timeZoneName')?.value || timezone;
        return `${timeStr} ${tzName}`;
      } catch {
        return `${timeStr} ${timezone}`;
      }
    },
    [timezone, formatSiteTime]
  );

  /**
   * Get current time in site's timezone
   */
  const getSiteCurrentTime = useCallback((): Date => {
    return toTimezone(new Date(), timezone);
  }, [timezone]);

  /**
   * Get the UTC offset string for the site's timezone
   */
  const getTimezoneOffset = useMemo(() => {
    try {
      const formatter = new Intl.DateTimeFormat('en', {
        timeZone: timezone,
        timeZoneName: 'longOffset',
      });
      const parts = formatter.formatToParts(new Date());
      const offset = parts.find(p => p.type === 'timeZoneName')?.value || 'UTC';
      return offset.replace('GMT', 'UTC');
    } catch {
      return 'UTC';
    }
  }, [timezone]);

  return {
    // Current settings
    timezone,
    timeFormat,
    dateFormat,
    timezoneOffset: getTimezoneOffset,
    
    // Formatters
    toSiteTime,
    formatSiteDate,
    formatSiteTime,
    formatSiteDateTime,
    formatSiteTimeWithZone,
    getSiteCurrentTime,
  };
}

/**
 * Available date formats for UI
 */
export const DATE_FORMATS = [
  { code: 'YYYY-MM-DD', example: '2024-12-31', description: 'ISO 8601' },
  { code: 'DD/MM/YYYY', example: '31/12/2024', description: 'European' },
  { code: 'MM/DD/YYYY', example: '12/31/2024', description: 'US' },
  { code: 'DD-MM-YYYY', example: '31-12-2024', description: 'European Alt' },
  { code: 'DD.MM.YYYY', example: '31.12.2024', description: 'German/Swiss' },
  { code: 'YYYY/MM/DD', example: '2024/12/31', description: 'Japanese' },
] as const;

/**
 * Available time formats for UI
 */
export const TIME_FORMATS = [
  { code: '24h', example: '14:30', description: '24-hour clock' },
  { code: '12h', example: '2:30 PM', description: '12-hour clock' },
] as const;

export default useSiteDateTime;
