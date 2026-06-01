// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Toast Hook
 * 
 * Provides a simplified toast API that wraps the Toast context.
 * Usage: const { toast } = useToast();
 *        toast({ title: "Success!", description: "Item saved." });
 *        toast({ title: "Error!", variant: "destructive" });
 */

import { useCallback } from 'react';
import { useToast as useToastContext } from '@/components/ui/toast';

interface ToastOptions {
  title: string;
  description?: string;
  variant?: 'default' | 'destructive';
  duration?: number;
}

export function useToast() {
  const { addToast } = useToastContext();

  const toast = useCallback((options: ToastOptions) => {
    const type = options.variant === 'destructive' ? 'error' : 'success';
    addToast({
      title: options.title,
      description: options.description,
      type,
      duration: options.duration,
    });
  }, [addToast]);

  return { toast };
}
