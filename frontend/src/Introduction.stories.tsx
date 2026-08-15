// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { Meta, StoryObj } from '@storybook/react-vite';

const meta: Meta = {
  title: 'Introduction',
  parameters: { layout: 'fullscreen' },
};

export default meta;

export const Welcome: StoryObj = {
  render: () => (
    <div className="max-w-3xl mx-auto p-8 prose prose-sm">
      <h1 className="text-3xl font-semibold tracking-tight">FreeSDN Design System</h1>
      <p className="mt-3 text-muted-foreground">
        Welcome to the FreeSDN component library. Every primitive in this catalog is used across
        the production app · what you see here is what ships.
      </p>

      <h2 className="mt-8 text-xl font-semibold">Conventions</h2>
      <ul className="mt-3 space-y-2 text-sm leading-6">
        <li>
          <strong>Semantic color tokens.</strong> Use{' '}
          <code className="bg-muted px-1 rounded text-xs">text-success</code>,{' '}
          <code className="bg-muted px-1 rounded text-xs">bg-destructive/10</code>,{' '}
          <code className="bg-muted px-1 rounded text-xs">text-muted-foreground</code>. Never
          hardcode color names like <code className="bg-muted px-1 rounded text-xs">text-emerald-500</code>.
          The token system handles light/dark and accent themes for free.
        </li>
        <li>
          <strong>Two stories per primitive minimum.</strong> A "happy path" story plus at least one
          edge case (empty, loading, overflowing, error). If a behavior matters, it has a story.
        </li>
        <li>
          <strong>Page-level primitives compose.</strong> A canonical list page is{' '}
          <code className="bg-muted px-1 rounded text-xs">PageHeader</code> +{' '}
          <code className="bg-muted px-1 rounded text-xs">StatsGrid</code> +{' '}
          <code className="bg-muted px-1 rounded text-xs">PageToolbar</code> +{' '}
          <code className="bg-muted px-1 rounded text-xs">DataTable selectable</code> +{' '}
          <code className="bg-muted px-1 rounded text-xs">BulkActionsBar</code>. Don't reinvent
          the toolbar.
        </li>
        <li>
          <strong>Tabs always scroll.</strong> <code className="bg-muted px-1 rounded text-xs">TabsList</code>{' '}
          handles overflow with edge fades, scroll chevrons, and active-tab auto-scroll. Never
          override with <code className="bg-muted px-1 rounded text-xs">flex-wrap</code> · overflow is the design.
        </li>
      </ul>

      <h2 className="mt-8 text-xl font-semibold">Categories</h2>
      <ul className="mt-3 space-y-2 text-sm leading-6">
        <li><strong>Primitives</strong> · Buttons, badges, tables, forms, tabs. The Lego bricks.</li>
        <li><strong>Layout</strong> · PageHeader, PageTabs, MainLayout. Page-shape building blocks.</li>
        <li><strong>System</strong> · ErrorBoundary, SectionBoundary. Resilience infrastructure.</li>
      </ul>

      <h2 className="mt-8 text-xl font-semibold">Error boundaries</h2>
      <p className="mt-2 text-sm">Three levels of containment, all wired automatically:</p>
      <table className="mt-3 text-sm w-full border-collapse">
        <thead>
          <tr className="border-b border-border">
            <th className="text-left py-2 pr-4 font-medium">Level</th>
            <th className="text-left py-2 pr-4 font-medium">Where</th>
            <th className="text-left py-2 font-medium">What it protects</th>
          </tr>
        </thead>
        <tbody className="text-muted-foreground">
          <tr className="border-b border-border/50">
            <td className="py-2 pr-4"><code>root</code></td>
            <td className="py-2 pr-4">main.tsx</td>
            <td className="py-2">Whole app · last line of defense</td>
          </tr>
          <tr className="border-b border-border/50">
            <td className="py-2 pr-4"><code>route</code></td>
            <td className="py-2 pr-4">MainLayout.tsx</td>
            <td className="py-2">Sidebar + topbar stay visible if the page crashes</td>
          </tr>
          <tr>
            <td className="py-2 pr-4"><code>section</code></td>
            <td className="py-2 pr-4">Around individual widgets</td>
            <td className="py-2">One widget can fail; the rest of the page keeps working</td>
          </tr>
        </tbody>
      </table>
      <p className="mt-3 text-sm text-muted-foreground">
        Use <code className="bg-muted px-1 rounded text-xs">SectionBoundary</code> (the shorthand)
        around dashboard widgets and tab contents.
      </p>

      <h2 className="mt-8 text-xl font-semibold">Tests</h2>
      <p className="mt-2 text-sm text-muted-foreground">
        Every primitive in this catalog has matching <code className="bg-muted px-1 rounded text-xs">*.test.tsx</code>{' '}
        smoke tests. Run <code className="bg-muted px-1 rounded text-xs">npm test</code> to verify
        the whole library is green.
      </p>
    </div>
  ),
};
