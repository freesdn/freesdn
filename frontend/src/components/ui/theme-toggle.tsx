// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { Moon, Sun, Monitor, Check } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useUIStore } from '../../stores';
import { motion, AnimatePresence } from 'framer-motion';

interface ThemeToggleProps {
  variant?: 'icon' | 'dropdown' | 'segmented';
  className?: string;
}

export function ThemeToggle({ variant = 'dropdown', className = '' }: ThemeToggleProps) {
  const { t } = useTranslation('common');
  const { theme, setTheme } = useUIStore();

  const themeLabel = t(`ThemeToggle.themes.${theme}`);

  if (variant === 'icon') {
    // Simple icon toggle (cycles through themes)
    const cycleTheme = () => {
      const themes: Array<'light' | 'dark' | 'system'> = ['light', 'dark', 'system'];
      const currentIndex = themes.indexOf(theme);
      const nextIndex = (currentIndex + 1) % themes.length;
      setTheme(themes[nextIndex]);
    };

    return (
      <button
        onClick={cycleTheme}
        className={`
          relative p-2 rounded-lg transition-all duration-200
          bg-secondary/50 hover:bg-secondary
          text-muted-foreground hover:text-foreground
          ${className}
        `}
        title={t('ThemeToggle.icon.title', { theme: themeLabel })}
        aria-label={t('ThemeToggle.icon.ariaLabel', { theme: themeLabel })}
      >
        <AnimatePresence mode="wait">
          {theme === 'light' && (
            <motion.div
              key="sun"
              initial={{ rotate: -90, opacity: 0 }}
              animate={{ rotate: 0, opacity: 1 }}
              exit={{ rotate: 90, opacity: 0 }}
              transition={{ duration: 0.15 }}
            >
              <Sun className="h-4 w-4" />
            </motion.div>
          )}
          {theme === 'dark' && (
            <motion.div
              key="moon"
              initial={{ rotate: -90, opacity: 0 }}
              animate={{ rotate: 0, opacity: 1 }}
              exit={{ rotate: 90, opacity: 0 }}
              transition={{ duration: 0.15 }}
            >
              <Moon className="h-4 w-4" />
            </motion.div>
          )}
          {theme === 'system' && (
            <motion.div
              key="system"
              initial={{ rotate: -90, opacity: 0 }}
              animate={{ rotate: 0, opacity: 1 }}
              exit={{ rotate: 90, opacity: 0 }}
              transition={{ duration: 0.15 }}
            >
              <Monitor className="h-4 w-4" />
            </motion.div>
          )}
        </AnimatePresence>
      </button>
    );
  }

  if (variant === 'segmented') {
    // Segmented control style (like iOS)
    return (
      <div
        role="group"
        aria-label={t('ThemeToggle.groupAriaLabel')}
        className={`
        inline-flex items-center p-1 rounded-lg
        bg-secondary/50 border border-border
        ${className}
      `}>
        {[
          { value: 'light' as const, icon: Sun, label: t('ThemeToggle.themes.light') },
          { value: 'dark' as const, icon: Moon, label: t('ThemeToggle.themes.dark') },
          { value: 'system' as const, icon: Monitor, label: t('ThemeToggle.themes.system') },
        ].map(({ value, icon: Icon, label }) => (
          <button
            key={value}
            onClick={() => setTheme(value)}
            className={`
              relative flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium
              transition-all duration-200
              ${theme === value
                ? 'bg-primary text-primary-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground hover:bg-secondary'
              }
            `}
            title={label}
          >
            <Icon className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">{label}</span>
          </button>
        ))}
      </div>
    );
  }

  // Default: Dropdown style
  return (
    <div className={`relative group ${className}`}>
      <button
        className={`
          flex items-center gap-2 px-3 py-2 rounded-lg
          bg-secondary/50 hover:bg-secondary border border-border
          text-sm font-medium text-foreground
          transition-all duration-200
        `}
        aria-label={t('ThemeToggle.dropdown.ariaLabel', { theme: themeLabel })}
      >
        {theme === 'light' && <Sun className="h-4 w-4" />}
        {theme === 'dark' && <Moon className="h-4 w-4" />}
        {theme === 'system' && <Monitor className="h-4 w-4" />}
        <span>{themeLabel}</span>
      </button>

      {/* Dropdown menu */}
      <div className="
        absolute right-0 top-full mt-1 py-1 min-w-[140px]
        bg-popover border border-border rounded-lg shadow-lg
        opacity-0 invisible group-hover:opacity-100 group-hover:visible
        transition-all duration-200 z-50
      ">
        {[
          { value: 'light' as const, icon: Sun, label: t('ThemeToggle.themes.light') },
          { value: 'dark' as const, icon: Moon, label: t('ThemeToggle.themes.dark') },
          { value: 'system' as const, icon: Monitor, label: t('ThemeToggle.themes.system') },
        ].map(({ value, icon: Icon, label }) => (
          <button
            key={value}
            onClick={() => setTheme(value)}
            className={`
              w-full flex items-center gap-2 px-3 py-2 text-sm
              transition-colors duration-150
              ${theme === value
                ? 'bg-primary/10 text-primary'
                : 'text-foreground hover:bg-secondary'
              }
            `}
          >
            <Icon className="h-4 w-4" />
            {label}
            {theme === value && (
              <Check className="ml-auto h-4 w-4 text-primary" />
            )}
          </button>
        ))}
      </div>
    </div>
  );
}
