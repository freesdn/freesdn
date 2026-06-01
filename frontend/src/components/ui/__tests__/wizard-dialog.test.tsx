// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { z } from 'zod';
import { WizardDialog, type WizardStep } from '../wizard-dialog';
import { FormControl, FormField, FormItem, FormLabel, FormMessage } from '../form';
import { Input } from '../input';

const schema = z.object({
  name: z.string().min(1, 'Name is required'),
  email: z.string().email('Must be a valid email'),
  enabled: z.boolean(),
});
type FormValues = z.infer<typeof schema>;

function makeSteps(opts: { validate?: (values: FormValues) => Promise<string | undefined> } = {}): WizardStep<FormValues>[] {
  return [
    {
      id: 'identity',
      label: 'Identity',
      fields: ['name'],
      content: (form) => (
        <FormField
          control={form.control}
          name="name"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Name</FormLabel>
              <FormControl><Input placeholder="Jane" {...field} /></FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
      ),
      validate: opts.validate,
    },
    {
      id: 'contact',
      label: 'Contact',
      fields: ['email'],
      content: (form) => (
        <FormField
          control={form.control}
          name="email"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Email</FormLabel>
              <FormControl><Input type="email" {...field} /></FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
      ),
    },
    {
      id: 'review',
      label: 'Review',
      fields: ['enabled'],
      content: () => <div data-testid="review-step">Review your details</div>,
    },
  ];
}

function renderHarness(opts: {
  open?: boolean;
  onSubmit?: (values: FormValues) => Promise<void> | void;
  onOpenChange?: (open: boolean) => void;
  validate?: (values: FormValues) => Promise<string | undefined>;
  /** Pre-fill values so we don't have to type through unmounted fields */
  defaultValues?: FormValues;
} = {}) {
  return render(
    <WizardDialog<FormValues>
      open={opts.open ?? true}
      onOpenChange={opts.onOpenChange ?? vi.fn()}
      title="Add user"
      description="Create a new user in 3 steps"
      schema={schema}
      defaultValues={opts.defaultValues ?? { name: '', email: '', enabled: true }}
      steps={makeSteps({ validate: opts.validate })}
      onSubmit={opts.onSubmit ?? vi.fn()}
      submitLabel="Create user"
    />
  );
}

describe('WizardDialog', () => {
  it('renders the title, description, and stepper', () => {
    renderHarness();
    expect(screen.getByText('Add user')).toBeInTheDocument();
    expect(screen.getByText('Create a new user in 3 steps')).toBeInTheDocument();
    expect(screen.getByLabelText('Wizard steps')).toBeInTheDocument();
    expect(screen.getByText('Identity')).toBeInTheDocument();
    expect(screen.getByText('Contact')).toBeInTheDocument();
    expect(screen.getByText('Review')).toBeInTheDocument();
  });

  it('starts on step 1: shows Next, no Back', () => {
    renderHarness();
    expect(screen.getByRole('button', { name: /^next$/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^back$/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /create user/i })).not.toBeInTheDocument();
  });

  it('marks the current step with aria-current', () => {
    renderHarness();
    const items = screen.getAllByRole('listitem');
    expect(items[0]).toHaveAttribute('aria-current', 'step');
    expect(items[1]).not.toHaveAttribute('aria-current');
  });

  it('blocks Next when current step has invalid fields', async () => {
    const user = userEvent.setup();
    renderHarness();
    await user.click(screen.getByRole('button', { name: /^next$/i }));
    expect(await screen.findByText('Name is required')).toBeInTheDocument();
    // Still on step 1
    expect(screen.getByLabelText('Name')).toBeInTheDocument();
  });

  it('advances to step 2 when current step is valid', async () => {
    const user = userEvent.setup();
    renderHarness();
    await user.type(screen.getByLabelText('Name'), 'Jane Doe');
    await user.click(screen.getByRole('button', { name: /^next$/i }));
    expect(await screen.findByLabelText('Email')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /^back$/i })).toBeInTheDocument();
  });

  it('Back returns to the previous step', async () => {
    const user = userEvent.setup();
    renderHarness({ defaultValues: { name: 'Jane', email: 'jane@example.com', enabled: true } });
    await user.click(screen.getByRole('button', { name: /^next$/i }));
    await screen.findByLabelText('Email');
    await user.click(screen.getByRole('button', { name: /^back$/i }));
    expect(screen.getByLabelText('Name')).toBeInTheDocument();
  });

  it('shows submit button (NOT Next) on the last step', async () => {
    const user = userEvent.setup();
    renderHarness();
    await user.type(screen.getByLabelText('Name'), 'Jane');
    await user.click(screen.getByRole('button', { name: /^next$/i }));
    await screen.findByLabelText('Email');
    await user.type(screen.getByLabelText('Email'), 'jane@example.com');
    await user.click(screen.getByRole('button', { name: /^next$/i }));
    expect(await screen.findByTestId('review-step')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /create user/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^next$/i })).not.toBeInTheDocument();
  });

  it('calls onSubmit with all values when submit clicked on final step', async () => {
    const onSubmit = vi.fn();
    const user = userEvent.setup();
    renderHarness({
      onSubmit,
      defaultValues: { name: 'Jane', email: 'jane@example.com', enabled: true },
    });
    await user.click(screen.getByRole('button', { name: /^next$/i }));
    await screen.findByLabelText('Email');
    await user.click(screen.getByRole('button', { name: /^next$/i }));
    await screen.findByTestId('review-step');
    await user.click(screen.getByRole('button', { name: /create user/i }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    expect(onSubmit.mock.calls[0][0]).toEqual({ name: 'Jane', email: 'jane@example.com', enabled: true });
  });

  it('async validate hook can block Next with an error string', async () => {
    const user = userEvent.setup();
    renderHarness({
      validate: async () => 'Backend says no',
      defaultValues: { name: 'Jane', email: 'jane@example.com', enabled: true },
    });
    await user.click(screen.getByRole('button', { name: /^next$/i }));
    expect(await screen.findByText('Backend says no')).toBeInTheDocument();
    // Did not advance · stepper still shows Identity as current
    const items = screen.getAllByRole('listitem');
    expect(items[0]).toHaveAttribute('aria-current', 'step');
    expect(items[1]).not.toHaveAttribute('aria-current');
  });

  it('shows server error banner when onSubmit throws', async () => {
    const user = userEvent.setup();
    renderHarness({
      onSubmit: vi.fn().mockRejectedValue(new Error('Network error')),
      defaultValues: { name: 'Jane', email: 'jane@example.com', enabled: true },
    });
    await user.click(screen.getByRole('button', { name: /^next$/i }));
    await screen.findByLabelText('Email');
    await user.click(screen.getByRole('button', { name: /^next$/i }));
    await screen.findByTestId('review-step');
    await user.click(screen.getByRole('button', { name: /create user/i }));
    expect(await screen.findByText('Network error')).toBeInTheDocument();
  });

  it('extracts axios error response.data.detail', async () => {
    const user = userEvent.setup();
    renderHarness({
      onSubmit: vi.fn().mockRejectedValue({
        response: { data: { detail: 'Email already exists' } },
      }),
      defaultValues: { name: 'Jane', email: 'jane@example.com', enabled: true },
    });
    await user.click(screen.getByRole('button', { name: /^next$/i }));
    await screen.findByLabelText('Email');
    await user.click(screen.getByRole('button', { name: /^next$/i }));
    await screen.findByTestId('review-step');
    await user.click(screen.getByRole('button', { name: /create user/i }));
    expect(await screen.findByText('Email already exists')).toBeInTheDocument();
  });

  it('Cancel calls onOpenChange(false)', async () => {
    const onOpenChange = vi.fn();
    const user = userEvent.setup();
    renderHarness({ onOpenChange });
    await user.click(screen.getByRole('button', { name: /^cancel$/i }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it('renders nothing when open=false', () => {
    renderHarness({ open: false });
    expect(screen.queryByText('Add user')).not.toBeInTheDocument();
  });

  it('shows successContent after successful submit (instead of closing)', async () => {
    const user = userEvent.setup();
    const onOpenChange = vi.fn();
    render(
      <WizardDialog<FormValues>
        open
        onOpenChange={onOpenChange}
        title="Add user"
        schema={schema}
        defaultValues={{ name: 'Jane', email: 'jane@example.com', enabled: true }}
        steps={makeSteps()}
        onSubmit={vi.fn()}
        submitLabel="Create user"
        successContent={(values, { close }) => (
          <div>
            <p data-testid="success-msg">Created {values.name}!</p>
            <button onClick={close} data-testid="close-success">Got it</button>
          </div>
        )}
        successCloseLabel="Done"
      />
    );
    // Advance to final step + submit
    await user.click(screen.getByRole('button', { name: /^next$/i }));
    await screen.findByLabelText('Email');
    await user.click(screen.getByRole('button', { name: /^next$/i }));
    await screen.findByTestId('review-step');
    await user.click(screen.getByRole('button', { name: /create user/i }));

    // Success view should appear; wizard chrome should not
    expect(await screen.findByTestId('success-msg')).toHaveTextContent('Created Jane!');
    expect(screen.queryByRole('button', { name: /^next$/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^back$/i })).not.toBeInTheDocument();
    // The "Done" close button is rendered
    expect(screen.getByRole('button', { name: 'Done' })).toBeInTheDocument();
    // onOpenChange should NOT be called yet (user has to click close)
    expect(onOpenChange).not.toHaveBeenCalledWith(false);

    // Click close in success view → onOpenChange(false)
    await user.click(screen.getByTestId('close-success'));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });
});
