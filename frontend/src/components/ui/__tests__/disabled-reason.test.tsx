// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, expect, it } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { DisabledReason } from '@/components/ui/disabled-reason';
import { Button } from '@/components/ui/button';

describe('DisabledReason', () => {
  it('renders the control unchanged when there is no reason', () => {
    const { container } = render(
      <DisabledReason>
        <Button>Save</Button>
      </DisabledReason>,
    );
    expect(container.firstElementChild?.tagName).toBe('BUTTON');
    expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled();
  });

  it('gives a disabled control a keyboard-reachable reason', async () => {
    render(
      <DisabledReason reason="Needs the cameras.manage_ptz permission">
        <Button disabled>Save preset</Button>
      </DisabledReason>,
    );
    const button = screen.getByRole('button', { name: 'Save preset' });
    expect(button).toBeDisabled();
    const wrapper = button.parentElement as HTMLElement;
    expect(wrapper.tagName).toBe('SPAN');
    expect(wrapper).toHaveAttribute('tabindex', '0');
    fireEvent.focus(wrapper);
    expect((await screen.findAllByText('Needs the cameras.manage_ptz permission')).length).toBeGreaterThan(0);
  });
});
