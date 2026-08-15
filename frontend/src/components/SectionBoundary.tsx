// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { ReactNode } from 'react';
import { ErrorBoundary } from './ErrorBoundary';

/**
 * Tiny convenience wrapper around `<ErrorBoundary level="section">`.
 *
 * Use it around individual widgets on dashboards / detail pages so a single
 * widget that throws shows a compact inline banner instead of blanking the
 * entire page.
 *
 *   <SectionBoundary>
 *     <NetworkHealthWidget ... />
 *   </SectionBoundary>
 */
export function SectionBoundary({
  children,
  resetKeys,
}: {
  children: ReactNode;
  /** Optional reset keys · when these change, the boundary resets. */
  resetKeys?: ReadonlyArray<unknown>;
}) {
  return (
    <ErrorBoundary level="section" resetKeys={resetKeys}>
      {children}
    </ErrorBoundary>
  );
}
