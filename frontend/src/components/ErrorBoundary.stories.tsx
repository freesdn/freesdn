// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { Meta, StoryObj } from '@storybook/react-vite';
import { useState } from 'react';
import { ErrorBoundary } from './ErrorBoundary';
import { SectionBoundary } from './SectionBoundary';

const meta: Meta<typeof ErrorBoundary> = {
  title: 'System/ErrorBoundary',
  component: ErrorBoundary,
  parameters: {
    layout: 'fullscreen',
    docs: {
      description: {
        component:
          'Three-level error boundary used app-wide. `level="root"` for the app shell, `level="route"` inside MainLayout to keep chrome visible, `level="section"` (or `<SectionBoundary>`) around individual widgets so one bad API response does not blank the page.',
      },
    },
  },
};

export default meta;
type Story = StoryObj<typeof ErrorBoundary>;

function Bomb({ message = 'Simulated render error' }: { message?: string }): never {
  throw new Error(message);
}

export const SectionLevel: Story = {
  name: 'level="section" (compact inline banner)',
  render: () => (
    <div className="p-6 max-w-2xl">
      <p className="text-sm text-muted-foreground mb-3">
        This is what one widget on a dashboard looks like when it crashes · the rest of the page keeps working.
      </p>
      <ErrorBoundary level="section">
        <Bomb message="Could not load device metrics" />
      </ErrorBoundary>
      <p className="text-sm text-muted-foreground mt-3">
        Other widgets render normally below.
      </p>
    </div>
  ),
};

export const RouteLevel: Story = {
  name: 'level="route" (page-sized card)',
  render: () => (
    <div className="min-h-[60vh] bg-background">
      <ErrorBoundary level="route">
        <Bomb message="Failed to fetch /api/v1/devices" />
      </ErrorBoundary>
    </div>
  ),
};

export const RootLevel: Story = {
  name: 'level="root" (full-screen)',
  render: () => (
    <ErrorBoundary level="root">
      <Bomb message="Application failed to initialize" />
    </ErrorBoundary>
  ),
};

export const RetryRecovers: Story = {
  name: 'Retry button recovers when state changes',
  render: () => {
    function Demo() {
      const [crashed, setCrashed] = useState(true);
      return (
        <div className="p-6 max-w-2xl space-y-3">
          <button
            className="text-xs px-3 py-1.5 border rounded hover:bg-muted"
            onClick={() => setCrashed((c) => !c)}
          >
            Toggle crash state ({crashed ? 'crashed' : 'healthy'})
          </button>
          <ErrorBoundary
            level="section"
            fallback={(err, reset) => (
              <div className="rounded border border-destructive/30 bg-destructive/5 p-3 text-sm">
                <p className="font-medium text-destructive">{err.message}</p>
                <button
                  className="mt-2 text-xs px-2 py-1 border rounded"
                  onClick={() => {
                    setCrashed(false);
                    reset();
                  }}
                >
                  Fix and retry
                </button>
              </div>
            )}
          >
            {crashed ? <Bomb /> : <p className="text-success">Component working normally</p>}
          </ErrorBoundary>
        </div>
      );
    }
    return <Demo />;
  },
};

export const SectionBoundaryShorthand: Story = {
  name: '<SectionBoundary> shorthand',
  render: () => (
    <div className="p-6 max-w-2xl">
      <p className="text-sm text-muted-foreground mb-3">
        Recommended: use <code>&lt;SectionBoundary&gt;</code> around dashboard widgets. It is just <code>&lt;ErrorBoundary level="section"&gt;</code>.
      </p>
      <SectionBoundary>
        <Bomb message="Widget API timed out" />
      </SectionBoundary>
    </div>
  ),
};
