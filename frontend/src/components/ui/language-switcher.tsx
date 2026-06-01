// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { Globe, Check } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { SUPPORTED_LOCALES, changeLanguage } from '@/lib/i18n';
import { Button } from './button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from './dropdown-menu';
import { cn } from '@/lib/utils';

/**
 * Compact language switcher (Globe icon → dropdown of supported locales).
 * Calls i18n.changeLanguage(), which applies live and caches the choice to
 * localStorage (freesdn_locale) so it persists across reloads.
 */
export function LanguageSwitcher() {
  const { i18n, t } = useTranslation('common');
  const current = i18n.resolvedLanguage || i18n.language || 'en';
  const active =
    SUPPORTED_LOCALES.find((l) => current.startsWith(l.code)) ?? SUPPORTED_LOCALES[0];

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="h-9 w-9"
          aria-label={t('changeLanguage', { defaultValue: 'Change language' })}
          title={t('changeLanguage', { defaultValue: 'Change language' })}
        >
          <Globe className="h-5 w-5" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-44">
        <DropdownMenuLabel>{t('language', { defaultValue: 'Language' })}</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {SUPPORTED_LOCALES.map((loc) => (
          <DropdownMenuItem
            key={loc.code}
            onClick={() => void changeLanguage(loc.code)}
            className="gap-2"
          >
            <Check className={cn('h-4 w-4', loc.code === active.code ? 'opacity-100' : 'opacity-0')} />
            <span>{loc.nativeName}</span>
            <span className="ml-auto text-xs text-muted-foreground">{loc.code.toUpperCase()}</span>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
