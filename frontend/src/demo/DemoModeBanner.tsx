// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useEffect } from 'react';
import { ExternalLink } from 'lucide-react';
import { useToastHelpers } from '@/components/ui/toast';
import { demoWriteMessage, isDemoMode } from './mode';

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

  return (
    <div className="fixed inset-x-0 bottom-0 z-[10000] border-t border-warning/30 bg-warning text-warning-foreground shadow-sm">
      <div className="mx-auto flex min-h-10 max-w-7xl items-center justify-between gap-3 px-4 py-2 text-xs sm:px-6 lg:px-8">
        <span className="font-medium">
          Demo - read-only, sample data.
        </span>
        <a
          href="https://freesdn.org"
          className="inline-flex items-center gap-1 font-semibold underline-offset-4 hover:underline"
        >
          Get the real thing
          <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
        </a>
      </div>
    </div>
  );
}
