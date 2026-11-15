// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * The batch progress dialog draws status from the theme's tokens (success,
 * info, destructive, warning), not fixed palette shades that ignore the
 * theme.
 */
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { BatchProgressDialog, type BatchDeviceStatus } from '../batch-progress-dialog';

const devices: BatchDeviceStatus[] = [
  { id: '1', name: 'core-sw-1', status: 'success' },
  { id: '2', name: 'core-sw-2', status: 'running' },
  { id: '3', name: 'edge-sw-1', status: 'failed', message: 'Timed out' },
  { id: '4', name: 'edge-sw-2', status: 'skipped' },
  { id: '5', name: 'edge-sw-3', status: 'pending' },
];

const RAW_PALETTE = /\b(text|bg)-(green|blue|red|yellow|amber|emerald|sky)-\d{2,3}\b/;

describe('BatchProgressDialog colours', () => {
  it('uses theme status tokens for every status', () => {
    render(<BatchProgressDialog open onOpenChange={() => {}} title="Reboot switches" devices={devices} />);
    const dialog = screen.getByRole('dialog');
    const classes = Array.from(dialog.querySelectorAll('[class]')).map((el) => el.getAttribute('class') ?? '');
    expect(classes.filter((c) => RAW_PALETTE.test(c))).toEqual([]);
    const all = classes.join(' ');
    for (const token of ['text-success', 'text-info', 'text-destructive', 'text-warning', 'bg-success', 'bg-destructive']) {
      expect(all).toContain(token);
    }
  });
});
