// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '../dialog';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from '../sheet';

describe('Dialog · accessibility', () => {
  it('renders with a DialogTitle (Radix a11y requirement)', () => {
    render(
      <Dialog open onOpenChange={() => {}}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add controller</DialogTitle>
            <DialogDescription>Register a new controller</DialogDescription>
          </DialogHeader>
          <div>Body content</div>
        </DialogContent>
      </Dialog>,
    );
    // Radix sets role="dialog" and uses the title as the accessible name.
    const dialog = screen.getByRole('dialog');
    expect(dialog).toHaveAccessibleName('Add controller');
  });

  it('built-in close button has an explicit aria-label (not just sr-only text)', () => {
    render(
      <Dialog open onOpenChange={() => {}}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Settings</DialogTitle>
          </DialogHeader>
        </DialogContent>
      </Dialog>,
    );
    const closeBtn = screen.getByRole('button', { name: /close dialog/i });
    expect(closeBtn).toHaveAttribute('aria-label', 'Close dialog');
    // Focus styles use focus-visible for keyboard-only ring (vs always-on focus)
    expect(closeBtn.className).toMatch(/focus-visible:ring-2/);
  });
});

describe('Sheet · accessibility', () => {
  it('renders with a SheetTitle and exposes it as the accessible name', () => {
    render(
      <Sheet open onOpenChange={() => {}}>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>Device details</SheetTitle>
            <SheetDescription>Inspect without leaving the page</SheetDescription>
          </SheetHeader>
        </SheetContent>
      </Sheet>,
    );
    expect(screen.getByRole('dialog')).toHaveAccessibleName('Device details');
  });

  it('close button has aria-label="Close panel" with focus-visible ring', () => {
    render(
      <Sheet open onOpenChange={() => {}}>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>Inspector</SheetTitle>
          </SheetHeader>
        </SheetContent>
      </Sheet>,
    );
    const closeBtn = screen.getByRole('button', { name: /close panel/i });
    expect(closeBtn).toHaveAttribute('aria-label', 'Close panel');
    expect(closeBtn.className).toMatch(/focus-visible:ring-2/);
  });
});
