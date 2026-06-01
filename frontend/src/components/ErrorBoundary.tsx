// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import React from 'react';
import { AlertTriangle, RotateCcw, Home } from 'lucide-react';
import i18n from '@/lib/i18n';

type ErrorBoundaryLevel = 'root' | 'route' | 'section';

interface ErrorBoundaryProps {
  children: React.ReactNode;
  /**
   * Visual treatment + recovery affordances:
   *  - 'root'    : full-screen fallback (reload + go-home buttons). Use ONCE at the app root.
   *  - 'route'   : page-sized inline card. Use inside layouts that should keep chrome (sidebar/topbar) visible.
   *  - 'section' : compact inline banner. Use around individual widgets so one bad card doesn't blank the whole page.
   *  Default: 'section'.
   */
  level?: ErrorBoundaryLevel;
  /**
   * Custom fallback UI. Receives the error + a reset callback.
   * If provided, overrides the level-based default fallback.
   */
  fallback?: (error: Error, reset: () => void) => React.ReactNode;
  /**
   * When any value in this array changes between renders, the boundary
   * automatically resets to its non-error state. Pass [location.pathname]
   * to auto-recover when the user navigates away from a crashed page.
   */
  resetKeys?: ReadonlyArray<unknown>;
  /**
   * Called when componentDidCatch fires. Useful for telemetry.
   */
  onError?: (error: Error, errorInfo: React.ErrorInfo) => void;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

function arraysEqual(a: ReadonlyArray<unknown> = [], b: ReadonlyArray<unknown> = []) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (!Object.is(a[i], b[i])) return false;
  return true;
}

/**
 * Translate a key in the `common` namespace, falling back to the supplied
 * English copy when the bundle isn't loaded. ErrorBoundary is a class
 * component (only class components can catch render errors), so it can't use
 * the `useTranslation` hook, we read from the shared i18n instance directly.
 * The `defaultValue` keeps copy correct before bundles load and in tests that
 * mount the boundary without translation resources.
 */
function tr(key: string, defaultValue: string, options?: Record<string, unknown>): string {
  return i18n.t(key, { ns: 'common', defaultValue, ...options });
}

/**
 * Generic error boundary. Catches render-time errors in its subtree and shows
 * a recovery UI sized to the boundary's `level`. Auto-resets when `resetKeys`
 * change so navigating away from a crashed page returns the user to a working state.
 */
export class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    if (import.meta.env.DEV) {
      console.error('[ErrorBoundary] Unhandled error:', error, errorInfo);
    }
    this.props.onError?.(error, errorInfo);
  }

  componentDidUpdate(prevProps: ErrorBoundaryProps) {
    if (
      this.state.hasError &&
      !arraysEqual(prevProps.resetKeys, this.props.resetKeys)
    ) {
      this.reset();
    }
  }

  reset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (!this.state.hasError || !this.state.error) {
      return this.props.children;
    }

    if (this.props.fallback) {
      return this.props.fallback(this.state.error, this.reset);
    }

    const level = this.props.level ?? 'section';

    if (level === 'root') {
      return (
        <div className="min-h-screen flex items-center justify-center bg-background p-4">
          <div className="text-center space-y-4 max-w-lg">
            <div className="text-5xl font-bold text-destructive">
              {tr('ErrorBoundary.root.badge', 'Error')}
            </div>
            <h1 className="text-2xl font-semibold">
              {tr('ErrorBoundary.root.title', 'Something went wrong')}
            </h1>
            <p className="text-muted-foreground">
              {tr('ErrorBoundary.root.description', 'An unexpected error occurred. Please try refreshing the page.')}
            </p>
            <pre className="mt-4 p-4 bg-muted rounded-md text-xs text-left overflow-auto max-h-40">
              {this.state.error.message}
            </pre>
            <div className="flex gap-4 justify-center pt-4">
              <button
                onClick={() => window.location.reload()}
                className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
              >
                {tr('ErrorBoundary.actions.refreshPage', 'Refresh Page')}
              </button>
              <button
                onClick={() => {
                  this.reset();
                  window.location.href = '/';
                }}
                className="px-4 py-2 border border-border rounded-md hover:bg-muted"
              >
                {tr('ErrorBoundary.actions.goToDashboard', 'Go to Dashboard')}
              </button>
            </div>
          </div>
        </div>
      );
    }

    if (level === 'route') {
      return (
        <div className="flex items-center justify-center min-h-[60vh] p-4">
          <div className="rounded-lg border border-destructive/40 bg-destructive/5 max-w-xl w-full p-6 text-center space-y-4">
            <div className="flex justify-center">
              <div className="h-12 w-12 rounded-full bg-destructive/10 flex items-center justify-center">
                <AlertTriangle className="h-6 w-6 text-destructive" />
              </div>
            </div>
            <div className="space-y-1">
              <h2 className="text-lg font-semibold">
                {tr('ErrorBoundary.route.title', 'This page crashed')}
              </h2>
              <p className="text-sm text-muted-foreground">
                {tr('ErrorBoundary.route.description', 'Something went wrong while rendering this page. The rest of the app should still work · try navigating somewhere else, or retry below.')}
              </p>
            </div>
            <pre className="mt-2 p-3 bg-muted/60 rounded-md text-[11px] text-left overflow-auto max-h-32 font-mono">
              {this.state.error.message}
            </pre>
            <div className="flex gap-2 justify-center pt-1">
              <button
                onClick={this.reset}
                className="inline-flex items-center gap-2 px-3 py-1.5 text-sm bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
              >
                <RotateCcw className="h-3.5 w-3.5" />
                {tr('ErrorBoundary.actions.retry', 'Retry')}
              </button>
              <button
                onClick={() => {
                  this.reset();
                  window.location.href = '/';
                }}
                className="inline-flex items-center gap-2 px-3 py-1.5 text-sm border border-border rounded-md hover:bg-muted"
              >
                <Home className="h-3.5 w-3.5" />
                {tr('ErrorBoundary.actions.goToDashboard', 'Go to Dashboard')}
              </button>
            </div>
          </div>
        </div>
      );
    }

    // section
    return (
      <div
        role="alert"
        className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm flex items-start gap-3"
      >
        <AlertTriangle className="h-4 w-4 text-destructive flex-shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          <p className="font-medium text-destructive">
            {tr('ErrorBoundary.section.title', 'This section failed to load')}
          </p>
          <p className="text-xs text-muted-foreground mt-0.5 truncate">
            {this.state.error.message}
          </p>
        </div>
        <button
          onClick={this.reset}
          className="inline-flex items-center gap-1 text-xs px-2 py-1 rounded border border-border hover:bg-muted"
        >
          <RotateCcw className="h-3 w-3" />
          {tr('ErrorBoundary.actions.retry', 'Retry')}
        </button>
      </div>
    );
  }
}
