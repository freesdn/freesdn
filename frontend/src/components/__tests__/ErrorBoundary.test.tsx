// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';
import { ErrorBoundary } from '../ErrorBoundary';

// Suppress React's noisy "consider adding error boundary" console output during tests.
let consoleError: ReturnType<typeof vi.spyOn>;
beforeEach(() => {
  consoleError = vi.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => {
  consoleError.mockRestore();
});

function Boom({ when }: { when: boolean }) {
  if (when) throw new Error('boom');
  return <div>safe</div>;
}

describe('ErrorBoundary', () => {
  it('renders children when there is no error', () => {
    render(
      <ErrorBoundary>
        <div>healthy content</div>
      </ErrorBoundary>
    );
    expect(screen.getByText('healthy content')).toBeInTheDocument();
  });

  it('catches errors and shows the section-level fallback by default', () => {
    render(
      <ErrorBoundary>
        <Boom when />
      </ErrorBoundary>
    );
    expect(screen.getByRole('alert')).toBeInTheDocument();
    expect(screen.getByText(/this section failed to load/i)).toBeInTheDocument();
    expect(screen.getByText(/boom/)).toBeInTheDocument();
  });

  it('shows the route-level fallback when level="route"', () => {
    render(
      <ErrorBoundary level="route">
        <Boom when />
      </ErrorBoundary>
    );
    expect(screen.getByText(/this page crashed/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /go to dashboard/i })).toBeInTheDocument();
  });

  it('shows the root-level fallback when level="root"', () => {
    render(
      <ErrorBoundary level="root">
        <Boom when />
      </ErrorBoundary>
    );
    expect(screen.getByText(/something went wrong/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /refresh page/i })).toBeInTheDocument();
  });

  it('uses the custom fallback render prop when provided', () => {
    render(
      <ErrorBoundary fallback={(err) => <div>custom: {err.message}</div>}>
        <Boom when />
      </ErrorBoundary>
    );
    expect(screen.getByText('custom: boom')).toBeInTheDocument();
  });

  it('Retry button resets the boundary to render children again', async () => {
    const user = userEvent.setup();

    function Toggle() {
      const [crashed, setCrashed] = useState(true);
      return (
        <ErrorBoundary
          level="section"
          fallback={(_err, reset) => (
            <button
              onClick={() => {
                setCrashed(false);
                reset();
              }}
            >
              Recover
            </button>
          )}
        >
          <Boom when={crashed} />
        </ErrorBoundary>
      );
    }

    render(<Toggle />);
    expect(screen.queryByText('safe')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Recover' }));
    expect(screen.getByText('safe')).toBeInTheDocument();
  });

  it('auto-resets when resetKeys change', () => {
    function Wrapper({ resetKey, crashed }: { resetKey: string; crashed: boolean }) {
      return (
        <ErrorBoundary resetKeys={[resetKey]}>
          <Boom when={crashed} />
        </ErrorBoundary>
      );
    }

    const { rerender } = render(<Wrapper resetKey="/a" crashed />);
    expect(screen.getByRole('alert')).toBeInTheDocument();

    // Change route key + stop crashing · boundary should reset and render the child
    rerender(<Wrapper resetKey="/b" crashed={false} />);
    expect(screen.getByText('safe')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('calls onError when a child throws', () => {
    const onError = vi.fn();
    render(
      <ErrorBoundary onError={onError}>
        <Boom when />
      </ErrorBoundary>
    );
    expect(onError).toHaveBeenCalledOnce();
    expect(onError.mock.calls[0][0]).toBeInstanceOf(Error);
    expect(onError.mock.calls[0][0].message).toBe('boom');
  });

  it('does NOT swallow rerender of healthy children when no error has occurred', () => {
    const { rerender } = render(
      <ErrorBoundary>
        <div>v1</div>
      </ErrorBoundary>
    );
    rerender(
      <ErrorBoundary>
        <div>v2</div>
      </ErrorBoundary>
    );
    expect(screen.getByText('v2')).toBeInTheDocument();
  });
});
