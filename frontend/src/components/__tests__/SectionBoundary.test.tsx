// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SectionBoundary } from '../SectionBoundary';

let consoleError: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => {
  consoleError.mockRestore();
});

function Boom({ when }: { when: boolean }) {
  if (when) throw new Error('widget crashed');
  return <div>widget content</div>;
}

describe('SectionBoundary', () => {
  it('renders children when there is no error', () => {
    render(
      <SectionBoundary>
        <div>healthy widget</div>
      </SectionBoundary>
    );
    expect(screen.getByText('healthy widget')).toBeInTheDocument();
  });

  it('renders the section-level fallback when a child throws', () => {
    render(
      <SectionBoundary>
        <Boom when />
      </SectionBoundary>
    );
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByText(/this section failed to load/i)).toBeInTheDocument();
    expect(screen.getByText(/widget crashed/)).toBeInTheDocument();
  });

  it('auto-resets when resetKeys change', () => {
    function Wrapper({ key, crashed }: { key: string; crashed: boolean }) {
      return (
        <SectionBoundary resetKeys={[key]}>
          <Boom when={crashed} />
        </SectionBoundary>
      );
    }
    const { rerender } = render(<Wrapper key="initial" crashed />);
    expect(screen.getByRole('alert')).toBeInTheDocument();

    rerender(<Wrapper key="changed" crashed={false} />);
    expect(screen.getByText('widget content')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });
});
