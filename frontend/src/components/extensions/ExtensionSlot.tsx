// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN - Extension Slot
 *
 * Renders all detail sections registered by enabled modules for a given
 * entity type. Each section is wrapped in Suspense + ErrorBoundary.
 */

import { Suspense, Component, type ReactNode } from 'react';
import { moduleManifests } from '@/modules';
import type { DetailSlot } from '@/modules/types';
import { Skeleton } from '@/components/ui/skeleton';

// ─────────────────────────────────────────────────────────────────────────────
// Error boundary
// ─────────────────────────────────────────────────────────────────────────────

interface ErrorBoundaryState {
  hasError: boolean;
}

class ExtensionErrorBoundary extends Component<
  { children: ReactNode; fallback: ReactNode },
  ErrorBoundaryState
> {
  state = { hasError: false };

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  render() {
    if (this.state.hasError) return this.props.fallback;
    return this.props.children;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Section skeleton
// ─────────────────────────────────────────────────────────────────────────────

function SectionSkeleton({ title }: { title: string }) {
  return (
    <div className="rounded-lg border bg-card p-4">
      <p className="mb-3 text-sm font-medium text-muted-foreground">{title}</p>
      <div className="space-y-2">
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-4 w-3/4" />
        <Skeleton className="h-4 w-1/2" />
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// ExtensionSlot component
// ─────────────────────────────────────────────────────────────────────────────

interface ExtensionSlotProps {
  /** Which entity detail page this slot is on */
  slot: DetailSlot;
  /** The entity's ID, passed to each injected component */
  entityId: string;
  /** Optional CSS class applied to the wrapper div */
  className?: string;
  /** Set of enabled module IDs (if not provided, all modules are considered enabled) */
  enabledModuleIds?: string[];
}

/**
 * Renders all `detailSections` from enabled modules that target the given slot.
 *
 * Usage in a device detail page:
 * ```tsx
 * <ExtensionSlot slot="device-detail" entityId={deviceId} />
 * ```
 */
export function ExtensionSlot({
  slot,
  entityId,
  className,
  enabledModuleIds,
}: ExtensionSlotProps) {
  const enabledSet = enabledModuleIds
    ? new Set(enabledModuleIds)
    : null; // null = all enabled

  const sections = moduleManifests
    .filter((m) => !enabledSet || enabledSet.has(m.id))
    .flatMap((m) => m.detailSections ?? [])
    .filter((s) => s.targetPage === slot)
    .sort((a, b) => (a.order ?? 99) - (b.order ?? 99));

  if (sections.length === 0) return null;

  return (
    <div className={className}>
      {sections.map((section) => (
        <ExtensionErrorBoundary key={section.id} fallback={null}>
          <Suspense fallback={<SectionSkeleton title={section.title} />}>
            <section.component entityId={entityId} />
          </Suspense>
        </ExtensionErrorBoundary>
      ))}
    </div>
  );
}
