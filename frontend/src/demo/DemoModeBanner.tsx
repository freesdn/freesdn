// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useEffect } from 'react';
import { BookOpen, ExternalLink } from 'lucide-react';
import { useToastHelpers } from '@/components/ui/toast';
import { demoWriteMessage, isDemoMode } from './mode';

/**
 * Persistent demo chrome for demo.freesdn.org.
 *
 * The two calls to action are the only way out of the demo, so they live here
 * rather than in the app header: this banner is fixed on every route, and the
 * header is shared with the real (non-demo) app.
 *
 * Colours are derived from `warning-foreground` on purpose. That token FLIPS
 * between themes (white in `:root`, near-black in `.dark`, both against the same
 * amber `--warning`), so anything hardcoded here would be unreadable in one of
 * them. Deriving the borders and fills from the same token the bar's own text
 * uses keeps both buttons legible in both themes by construction.
 */
export function DemoModeBanner() {
  const toast = useToastHelpers();

  useEffect(() => {
    if (!isDemoMode) return;
    document.documentElement.classList.add('demo-mode');
    return () => document.documentElement.classList.remove('demo-mode');
  }, []);

  useEffect(() => {
    if (!isDemoMode) return;
    const handler = () => {
      toast.warning('Read-only demo', demoWriteMessage);
    };
    window.addEventListener('freesdn-demo-write-blocked', handler);
    return () => window.removeEventListener('freesdn-demo-write-blocked', handler);
  }, [toast]);

  if (!isDemoMode) return null;

  const base =
    'inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-semibold ' +
    'transition-colors focus-visible:outline-none focus-visible:ring-2 ' +
    'focus-visible:ring-warning-foreground focus-visible:ring-offset-1 ' +
    'focus-visible:ring-offset-warning';

  return (
    <div className="fixed inset-x-0 bottom-0 z-[10000] border-t border-warning/30 bg-warning text-warning-foreground shadow-sm">
      <div className="mx-auto flex min-h-10 max-w-7xl flex-wrap items-center justify-between gap-x-3 gap-y-1.5 px-4 py-2 text-xs sm:px-6 lg:px-8">
        <span className="font-medium">
          Demo - read-only, sample data.
        </span>

        <div className="flex items-center gap-2">
          {/* Reference material: new tab, so the demo is not lost. */}
          <a
            href="https://docs.freesdn.org"
            target="_blank"
            rel="noopener noreferrer"
            className={`${base} border border-warning-foreground/35 hover:bg-warning-foreground/10`}
          >
            <BookOpen className="h-3.5 w-3.5" aria-hidden="true" />
            Docs
          </a>

          {/* Conversion action: same tab, this is a deliberate exit. */}
          <a
            href="https://freesdn.org"
            className={`${base} border border-warning-foreground/45 bg-warning-foreground/15 hover:bg-warning-foreground/25`}
          >
            Get FreeSDN
            <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
          </a>
        </div>
      </div>
    </div>
  );
}
