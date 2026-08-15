// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { z } from 'zod';
import { FormDialog } from '../form-dialog';
import { FormControl, FormField, FormItem, FormLabel, FormMessage } from '../form';
import { Input } from '../input';

const schema = z.object({
  name: z.string().min(1, 'Name is required'),
  port: z.coerce.number().int().positive('Port must be positive'),
});

type FormValues = z.infer<typeof schema>;

function Harness({
  open = true,
  onSubmit = vi.fn(),
  onOpenChange = vi.fn(),
  defaultValues = { name: '', port: 443 } as Partial<FormValues>,
}: {
  open?: boolean;
  onSubmit?: (values: FormValues) => Promise<void> | void;
  onOpenChange?: (open: boolean) => void;
  defaultValues?: Partial<FormValues>;
}) {
  return (
    <FormDialog<FormValues>
      open={open}
      onOpenChange={onOpenChange}
      title="Add controller"
      description="Register a new controller"
      schema={schema}
      defaultValues={defaultValues as FormValues}
      onSubmit={onSubmit}
      submitLabel="Create"
    >
      {(form) => (
        <>
          <FormField
            control={form.control}
            name="name"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Name</FormLabel>
                <FormControl>
                  <Input placeholder="My controller" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
          <FormField
            control={form.control}
            name="port"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Port</FormLabel>
                <FormControl>
                  <Input type="number" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </>
      )}
    </FormDialog>
  );
}

describe('FormDialog', () => {
  it('renders the title, description, fields, and footer buttons', () => {
    render(<Harness />);
    expect(screen.getByText('Add controller')).toBeInTheDocument();
    expect(screen.getByText('Register a new controller')).toBeInTheDocument();
    expect(screen.getByLabelText(/name/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/port/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeInTheDocument();
  });

  it('shows zod validation errors when fields are invalid', async () => {
    const onSubmit = vi.fn();
    const user = userEvent.setup();
    render(<Harness onSubmit={onSubmit} />);
    await user.click(screen.getByRole('button', { name: 'Create' }));
    expect(await screen.findByText('Name is required')).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('calls onSubmit with parsed values when fields are valid', async () => {
    const onSubmit = vi.fn();
    const user = userEvent.setup();
    render(<Harness onSubmit={onSubmit} defaultValues={{ name: '', port: 443 }} />);
    await user.type(screen.getByLabelText(/name/i), 'my-controller');
    await user.click(screen.getByRole('button', { name: 'Create' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledOnce());
    const [values] = onSubmit.mock.calls[0];
    expect(values).toEqual({ name: 'my-controller', port: 443 });
  });

  it('shows server error banner when onSubmit throws', async () => {
    const onSubmit = vi.fn().mockRejectedValue(new Error('Backend says no'));
    const user = userEvent.setup();
    render(<Harness onSubmit={onSubmit} defaultValues={{ name: 'x', port: 1 }} />);
    await user.click(screen.getByRole('button', { name: 'Create' }));
    expect(await screen.findByText('Backend says no')).toBeInTheDocument();
  });

  it('extracts axios-style detail field from a server error', async () => {
    const onSubmit = vi.fn().mockRejectedValue({
      response: { data: { detail: 'Controller name already exists' } },
    });
    const user = userEvent.setup();
    render(<Harness onSubmit={onSubmit} defaultValues={{ name: 'dup', port: 80 }} />);
    await user.click(screen.getByRole('button', { name: 'Create' }));
    expect(await screen.findByText('Controller name already exists')).toBeInTheDocument();
  });

  it('calls onOpenChange(false) when Cancel is clicked', async () => {
    const onOpenChange = vi.fn();
    const user = userEvent.setup();
    render(<Harness onOpenChange={onOpenChange} />);
    await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it('does not render dialog content when open=false', () => {
    render(<Harness open={false} />);
    expect(screen.queryByText('Add controller')).not.toBeInTheDocument();
  });
});
