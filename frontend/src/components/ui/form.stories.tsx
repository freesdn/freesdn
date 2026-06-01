// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { Meta, StoryObj } from '@storybook/react-vite';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from './form';
import { Input } from './input';
import { Button } from './button';

const meta: Meta = {
  title: 'Primitives/Form',
  parameters: {
    layout: 'padded',
    docs: {
      description: {
        component:
          'shadcn-style Form primitives wired to react-hook-form. Use these inside `<FormDialog>` or directly when you need a form outside a dialog. Each `<FormField>` auto-binds id + aria-describedby + aria-invalid.',
      },
    },
  },
};

export default meta;
type Story = StoryObj;

const schema = z.object({
  name: z.string().min(1, 'Name is required').max(40),
  email: z.string().email('Must be a valid email'),
});
type FormValues = z.infer<typeof schema>;

export const StandaloneForm: Story = {
  render: () => {
    function Demo() {
      const form = useForm<FormValues>({
        resolver: zodResolver(schema),
        defaultValues: { name: '', email: '' },
      });
      return (
        <Form {...form}>
          <form
            onSubmit={form.handleSubmit((values) => alert(JSON.stringify(values, null, 2)))}
            className="space-y-4 max-w-sm"
          >
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Name</FormLabel>
                  <FormControl><Input placeholder="Jane Doe" {...field} /></FormControl>
                  <FormDescription>Your full name as you'd like it displayed.</FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="email"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Email</FormLabel>
                  <FormControl><Input type="email" placeholder="jane@example.com" {...field} /></FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <Button type="submit">Submit</Button>
          </form>
        </Form>
      );
    }
    return <Demo />;
  },
};

export const WithValidationError: Story = {
  name: 'With pre-populated validation errors',
  render: () => {
    function Demo() {
      const form = useForm<FormValues>({
        resolver: zodResolver(schema),
        defaultValues: { name: '', email: 'not-an-email' },
        mode: 'onChange',
      });
      // Trigger validation immediately so errors show on mount
      void form.trigger();
      return (
        <Form {...form}>
          <form className="space-y-4 max-w-sm">
            <FormField
              control={form.control}
              name="name"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Name</FormLabel>
                  <FormControl><Input {...field} /></FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="email"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Email</FormLabel>
                  <FormControl><Input {...field} /></FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          </form>
        </Form>
      );
    }
    return <Demo />;
  },
};
