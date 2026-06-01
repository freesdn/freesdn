// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ToastProvider, useToastHelpers } from '../toast';

/**
 * A11y regression tests for the toast system.
 *
 * The toast container previously had no ARIA wiring, screen-reader users
 * received zero feedback when actions produced success/error toasts.
 * These tests pin the structural wiring so a future refactor can't silently
 * strip it:
 *
 *   - container has ``role="region"`` + ``aria-label="Notifications"``
 *   - container has ``aria-live="polite"`` so non-critical toasts are
 *     announced without interrupting the user
 *   - error/warning ``ToastItem`` elements escalate to ``role="alert"``
 *     so they're announced immediately
 *   - success/info toasts use ``role="status"``
 *   - the dismiss button has an ``aria-label`` (otherwise it's an
 *     icon-only button with no screen-reader text)
 */

// A tiny in-render fire-er, calls useToastHelpers via a useEffect so the
// toast is queued AFTER ToastProvider mounts. Using a side-effect avoids
// "useToast called outside ToastProvider" errors.
import { useEffect } from 'react';

function FireToast({
  type,
  title = 'hello',
  description,
}: {
  type: 'success' | 'error' | 'warning' | 'info';
  title?: string;
  description?: string;
}) {
  const helpers = useToastHelpers();
  useEffect(() => {
    helpers[type](title, description);
    // intentionally fire once; effect deps frozen.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return null;
}

describe('Toast · accessibility', () => {
  it('container exposes role=region + aria-live=polite + aria-label', () => {
    render(
      <ToastProvider>
        <FireToast type="info" />
      </ToastProvider>,
    );

    const region = screen.getByRole('region', { name: /notifications/i });
    expect(region).toBeInTheDocument();
    expect(region).toHaveAttribute('aria-live', 'polite');
    // aria-atomic="false" so newly mounted toasts are read incrementally,
    // not as a re-read of every visible toast.
    expect(region).toHaveAttribute('aria-atomic', 'false');
  });

  it('error toast carries role="alert" for immediate announcement', async () => {
    render(
      <ToastProvider>
        <FireToast type="error" title="Save failed" description="server 500" />
      </ToastProvider>,
    );

    // The error item exposes role="alert", distinct from the container's
    // role="region", and getByRole returns the item, not the region.
    const alert = await screen.findByRole('alert');
    expect(alert).toBeInTheDocument();
    expect(alert).toHaveTextContent('Save failed');
  });

  it('warning toast also carries role="alert"', async () => {
    render(
      <ToastProvider>
        <FireToast type="warning" title="Heads up" />
      </ToastProvider>,
    );

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Heads up');
  });

  it('success toast uses role="status" (polite, not interrupting)', async () => {
    render(
      <ToastProvider>
        <FireToast type="success" title="Saved" />
      </ToastProvider>,
    );

    // status items are also live regions but don't interrupt screen
    // readers mid-sentence, appropriate for success/info confirmations.
    const status = await screen.findByRole('status');
    expect(status).toHaveTextContent('Saved');
  });

  it('info toast uses role="status"', async () => {
    render(
      <ToastProvider>
        <FireToast type="info" title="Heads up" />
      </ToastProvider>,
    );

    const status = await screen.findByRole('status');
    expect(status).toHaveTextContent('Heads up');
  });

  it('dismiss button has an accessible label', async () => {
    render(
      <ToastProvider>
        <FireToast type="info" title="hi" />
      </ToastProvider>,
    );

    // Otherwise the icon-only X is unreachable for screen readers; they
    // would hear "button" with no idea what it does.
    const dismiss = await screen.findByRole('button', {
      name: /dismiss notification/i,
    });
    expect(dismiss).toBeInTheDocument();
  });
});
