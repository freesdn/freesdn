// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useEffect, useLayoutEffect } from 'react';
import { useUIStore, ACCENT_PRESETS } from '../../stores';

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const { theme, accentColor, animationsEnabled } = useUIStore();

  // ── Apply light / dark class before paint ──────────────────
  useLayoutEffect(() => {
    const root = window.document.documentElement;
    
    // Remove both classes first
    root.classList.remove('light', 'dark');
    
    if (theme === 'system') {
      // Check system preference
      const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light';
      root.classList.add(systemTheme);
    } else {
      root.classList.add(theme);
    }
  }, [theme]);

  // ── Apply accent color CSS custom properties ───────────────
  useLayoutEffect(() => {
    const root = window.document.documentElement;
    const preset = ACCENT_PRESETS.find((p) => p.id === accentColor) ?? ACCENT_PRESETS[0];

    // Determine the effective mode (light or dark)
    const isDark =
      theme === 'dark' ||
      (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);

    const values = isDark ? preset.dark : preset.light;

    root.style.setProperty('--primary', values.primary);
    root.style.setProperty('--primary-foreground', values.primaryForeground);
    root.style.setProperty('--ring', values.ring);
    root.style.setProperty('--sidebar-accent', values.sidebarAccent);
    root.style.setProperty('--chart-1', values.chart1);
  }, [accentColor, theme]);

  // ── Animations toggle ──────────────────────────────────────
  useLayoutEffect(() => {
    const root = window.document.documentElement;
    if (!animationsEnabled) {
      root.classList.add('no-animations');
    } else {
      root.classList.remove('no-animations');
    }
  }, [animationsEnabled]);

  // ── System theme media-query listener ──────────────────────
  useEffect(() => {
    if (theme !== 'system') return;

    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    
    const handleChange = (e: MediaQueryListEvent) => {
      const root = window.document.documentElement;
      root.classList.remove('light', 'dark');
      root.classList.add(e.matches ? 'dark' : 'light');

      // Re-apply accent vars for new mode
      const preset = ACCENT_PRESETS.find((p) => p.id === accentColor) ?? ACCENT_PRESETS[0];
      const values = e.matches ? preset.dark : preset.light;
      root.style.setProperty('--primary', values.primary);
      root.style.setProperty('--primary-foreground', values.primaryForeground);
      root.style.setProperty('--ring', values.ring);
      root.style.setProperty('--sidebar-accent', values.sidebarAccent);
      root.style.setProperty('--chart-1', values.chart1);
    };

    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, [theme, accentColor]);

  return <>{children}</>;
}
