// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useState, useCallback, useEffect, createContext, useContext, ReactNode } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { CheckCircle, AlertCircle, AlertTriangle, Info, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { cn } from '../../lib/utils';
import { registerMutationErrorHandler } from '../../lib/toastBridge';
import { getApiErrorMessage } from '../../lib/api/client';

type ToastType = 'success' | 'error' | 'warning' | 'info';

interface Toast {
  id: string;
  title: string;
  description?: string;
  type: ToastType;
  duration?: number;
  action?: {
    label: string;
    onClick: () => void;
  };
}

interface ToastContextValue {
  toasts: Toast[];
  addToast: (toast: Omit<Toast, 'id'>) => string;
  removeToast: (id: string) => void;
  clearAll: () => void;
}

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
}

// Convenience hooks
export function useToastHelpers() {
  const { addToast } = useToast();
  
  return {
    success: (title: string, description?: string) => 
      addToast({ title, description, type: 'success' }),
    error: (title: string, description?: string) => 
      addToast({ title, description, type: 'error', duration: 8000 }),
    warning: (title: string, description?: string) => 
      addToast({ title, description, type: 'warning', duration: 6000 }),
    info: (title: string, description?: string) => 
      addToast({ title, description, type: 'info' }),
  };
}

const icons: Record<ToastType, typeof CheckCircle> = {
  success: CheckCircle,
  error: AlertCircle,
  warning: AlertTriangle,
  info: Info,
};

const styles: Record<ToastType, string> = {
  success: 'bg-success/10 border-success/30 text-success',
  error: 'bg-destructive/10 border-destructive/30 text-destructive',
  warning: 'bg-warning/10 border-warning/30 text-warning',
  info: 'bg-primary/10 border-primary/30 text-primary',
};

interface ToastItemProps {
  toast: Toast;
  onRemove: (id: string) => void;
}

function ToastItem({ toast, onRemove }: ToastItemProps) {
  const { t } = useTranslation('common');
  const Icon = icons[toast.type];
  // A11Y: error + warning toasts use
  // ``role="alert"`` (implicit ``aria-live="assertive"``) because the
  // user must be notified immediately, they often signal failed
  // actions the user is still committing to. Success + info use the
  // surrounding container's polite live region (no per-item role
  // needed, they'd compete with the container's announcement).
  const itemRole = toast.type === 'error' || toast.type === 'warning'
    ? 'alert'
    : 'status';

  return (
    <motion.div
      role={itemRole}
      layout
      initial={{ opacity: 0, y: 50, scale: 0.9 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, y: 20, scale: 0.9 }}
      transition={{ duration: 0.2 }}
      className={cn(
        'flex items-start gap-3 p-4 rounded-lg border shadow-lg bg-background/95 backdrop-blur-sm min-w-[320px] max-w-[420px]',
        styles[toast.type]
      )}
    >
      <div className="shrink-0 mt-0.5" aria-hidden="true">
        <Icon className="h-5 w-5" />
      </div>
      <div className="flex-1 min-w-0">
        <h4 className="font-semibold text-foreground">{toast.title}</h4>
        {toast.description && (
          <p className="text-sm text-muted-foreground mt-1">
            {toast.description}
          </p>
        )}
        {toast.action && (
          <button
            onClick={toast.action.onClick}
            className="text-sm font-medium underline-offset-4 hover:underline mt-2"
          >
            {toast.action.label}
          </button>
        )}
      </div>
      <button
        type="button"
        onClick={() => onRemove(toast.id)}
        aria-label={t('Toast.dismiss')}
        className="shrink-0 text-muted-foreground hover:text-foreground transition-colors rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
      >
        <X className="h-4 w-4" aria-hidden="true" />
      </button>
    </motion.div>
  );
}

// Bridges the non-React MutationCache global onError (queryClient.ts) into the
// React toast context. Renders nothing; registers a stable handler on mount so
// any mutation without its own onError still surfaces a uniform error toast.
function GlobalMutationErrorBridge() {
  const { addToast } = useToast();
  const { t } = useTranslation('common');
  useEffect(() => {
    registerMutationErrorHandler((error) => {
      addToast({
        title: t('Toast.errorTitle'),
        description: getApiErrorMessage(error),
        type: 'error',
        duration: 8000,
      });
    });
    return () => registerMutationErrorHandler(null);
  }, [addToast, t]);
  return null;
}

interface ToastProviderProps {
  children: ReactNode;
}

export function ToastProvider({ children }: ToastProviderProps) {
  const { t } = useTranslation('common');
  const [toasts, setToasts] = useState<Toast[]>([]);

  const addToast = useCallback((toast: Omit<Toast, 'id'>) => {
    const id = Math.random().toString(36).substring(7);
    const newToast: Toast = { ...toast, id };
    
    setToasts((prev) => [...prev, newToast]);
    
    // Auto-dismiss
    const duration = toast.duration ?? 5000;
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, duration);
    
    return id;
  }, []);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const clearAll = useCallback(() => {
    setToasts([]);
  }, []);

  return (
    <ToastContext.Provider value={{ toasts, addToast, removeToast, clearAll }}>
      <GlobalMutationErrorBridge />
      {children}
      {/* Toast Container, A11Y.
          ``role="region"`` + ``aria-label`` lets screen-reader users
          navigate to the toast area with a region-jump shortcut.
          ``aria-live="polite"`` ensures non-critical additions are
          announced without interrupting the user; individual error/
          warning ToastItems escalate to ``role="alert"`` for
          immediate announcement. ``aria-atomic="false"`` so newly
          mounted toasts are read incrementally, not as a re-read of
          every visible toast.
      */}
      <div
        role="region"
        aria-label={t('Toast.region')}
        aria-live="polite"
        aria-atomic="false"
        className="fixed bottom-4 right-4 z-[9999] flex flex-col gap-2 pointer-events-none"
      >
        <AnimatePresence mode="popLayout">
          {toasts.map((toast) => (
            <div key={toast.id} className="pointer-events-auto">
              <ToastItem toast={toast} onRemove={removeToast} />
            </div>
          ))}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  );
}

// Alias for App.tsx compatibility
export const Toaster = ToastProvider;
