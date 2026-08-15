// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '../tabs';

function renderBasic() {
  return render(
    <Tabs defaultValue="one">
      <TabsList>
        <TabsTrigger value="one">One</TabsTrigger>
        <TabsTrigger value="two">Two</TabsTrigger>
        <TabsTrigger value="three">Three</TabsTrigger>
      </TabsList>
      <TabsContent value="one">Content one</TabsContent>
      <TabsContent value="two">Content two</TabsContent>
      <TabsContent value="three">Content three</TabsContent>
    </Tabs>
  );
}

describe('Tabs', () => {
  it('renders all triggers + the default tab content', () => {
    renderBasic();
    expect(screen.getByRole('tab', { name: 'One' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Two' })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Three' })).toBeInTheDocument();
    expect(screen.getByText('Content one')).toBeInTheDocument();
    expect(screen.queryByText('Content two')).not.toBeInTheDocument();
  });

  it('switches content when a different trigger is clicked', async () => {
    const user = userEvent.setup();
    renderBasic();
    await user.click(screen.getByRole('tab', { name: 'Two' }));
    expect(screen.getByText('Content two')).toBeInTheDocument();
    expect(screen.queryByText('Content one')).not.toBeInTheDocument();
  });

  it('marks the active trigger via data-state="active"', async () => {
    const user = userEvent.setup();
    renderBasic();
    const triggerTwo = screen.getByRole('tab', { name: 'Two' });
    expect(triggerTwo).toHaveAttribute('data-state', 'inactive');
    await user.click(triggerTwo);
    expect(triggerTwo).toHaveAttribute('data-state', 'active');
  });

  it('respects controlled value prop', () => {
    const { rerender } = render(
      <Tabs value="two" onValueChange={() => {}}>
        <TabsList>
          <TabsTrigger value="one">One</TabsTrigger>
          <TabsTrigger value="two">Two</TabsTrigger>
        </TabsList>
        <TabsContent value="one">Content one</TabsContent>
        <TabsContent value="two">Content two</TabsContent>
      </Tabs>
    );
    expect(screen.getByText('Content two')).toBeInTheDocument();

    rerender(
      <Tabs value="one" onValueChange={() => {}}>
        <TabsList>
          <TabsTrigger value="one">One</TabsTrigger>
          <TabsTrigger value="two">Two</TabsTrigger>
        </TabsList>
        <TabsContent value="one">Content one</TabsContent>
        <TabsContent value="two">Content two</TabsContent>
      </Tabs>
    );
    expect(screen.getByText('Content one')).toBeInTheDocument();
  });

  it('preserves user-provided className on the inner primitive', () => {
    render(
      <Tabs defaultValue="one">
        <TabsList className="custom-list-class">
          <TabsTrigger value="one">One</TabsTrigger>
        </TabsList>
        <TabsContent value="one">x</TabsContent>
      </Tabs>
    );
    // The custom class should land on the inner Radix primitive (role=tablist)
    const list = screen.getByRole('tablist');
    expect(list.className).toContain('custom-list-class');
  });

  it('keyboard arrow keys navigate between triggers (Radix a11y)', async () => {
    const user = userEvent.setup();
    renderBasic();
    const one = screen.getByRole('tab', { name: 'One' });
    one.focus();
    await user.keyboard('{ArrowRight}');
    // Radix moves focus and activates next tab
    expect(screen.getByRole('tab', { name: 'Two' })).toHaveFocus();
  });

  it('arrow keys wrap from last tab back to first (Radix default loop=true)', async () => {
    const user = userEvent.setup();
    renderBasic();
    const three = screen.getByRole('tab', { name: 'Three' });
    three.focus();
    await user.keyboard('{ArrowRight}');
    expect(screen.getByRole('tab', { name: 'One' })).toHaveFocus();
  });

  it('TabsTrigger declares focus-visible ring classes (keyboard a11y)', () => {
    renderBasic();
    const tab = screen.getByRole('tab', { name: 'One' });
    // The whole point: keyboard users MUST get a visible focus ring.
    // Asserting on classes (rather than computed style) keeps the test
    // independent of jsdom's incomplete CSS support.
    expect(tab.className).toMatch(/focus-visible:ring-2/);
    expect(tab.className).toMatch(/focus-visible:ring-ring/);
  });

  it('Tab key into the strip lands on the active tab (Radix roving tabindex)', async () => {
    const user = userEvent.setup();
    render(
      <>
        <button>before</button>
        <Tabs defaultValue="two">
          <TabsList>
            <TabsTrigger value="one">One</TabsTrigger>
            <TabsTrigger value="two">Two</TabsTrigger>
            <TabsTrigger value="three">Three</TabsTrigger>
          </TabsList>
          <TabsContent value="one">Content one</TabsContent>
          <TabsContent value="two">Content two</TabsContent>
          <TabsContent value="three">Content three</TabsContent>
        </Tabs>
      </>,
    );
    screen.getByRole('button', { name: 'before' }).focus();
    await user.tab();
    // Roving tabindex = the active tab is the only one in the tab order.
    expect(screen.getByRole('tab', { name: 'Two' })).toHaveFocus();
  });
});
