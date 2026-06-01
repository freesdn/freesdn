// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { Meta, StoryObj } from '@storybook/react-vite';
import { useState } from 'react';
import { z } from 'zod';
import { FormDialog } from './form-dialog';
import { FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from './form';
import { Input } from './input';
import { Button } from './button';

const meta: Meta<typeof FormDialog> = {
  title: 'Primitives/FormDialog',
  component: FormDialog,
  parameters: {
    layout: 'centered',
    docs: {
      description: {
        component:
          'Unified create/edit dialog. Pass a zod schema and default values; children render the fields inside a react-hook-form context. The dialog handles loading state, form reset, and server error display automatically.',
      },
    },
  },
};

export default meta;

const controllerSchema = z.object({
  name: z.string().min(1, 'Name is required').max(40),
  host: z.string().url('Must be a valid URL'),
  port: z.coerce.number().int().min(1).max(65535),
  description: z.string().optional(),
});
type ControllerForm = z.infer<typeof controllerSchema>;

export const CreateController: StoryObj = {
  render: () => {
    function Demo() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <Button onClick={() => setOpen(true)}>Add controller…</Button>
          <FormDialog<ControllerForm>
            open={open}
            onOpenChange={setOpen}
            title="Add controller"
            description="Register a new network controller"
            schema={controllerSchema}
            defaultValues={{ name: '', host: '', port: 443, description: '' }}
            submitLabel="Create"
            onSubmit={async (values) => {
              await new Promise((r) => setTimeout(r, 800));
              alert(`Created: ${JSON.stringify(values)}`);
            }}
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
                        <Input placeholder="e.g. omada-prod-01" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="host"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Host URL</FormLabel>
                      <FormControl>
                        <Input placeholder="https://omada.local" {...field} />
                      </FormControl>
                      <FormDescription>The full URL including protocol.</FormDescription>
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
        </>
      );
    }
    return <Demo />;
  },
};

export const ServerErrorBanner: StoryObj = {
  name: 'Server error banner',
  render: () => {
    function Demo() {
      const [open, setOpen] = useState(true);
      return (
        <FormDialog
          open={open}
          onOpenChange={setOpen}
          title="Add controller"
          schema={z.object({ name: z.string().min(1) })}
          defaultValues={{ name: 'duplicate' }}
          submitLabel="Create"
          onSubmit={async () => {
            await new Promise((r) => setTimeout(r, 400));
            // Simulate axios error shape
            throw { response: { data: { detail: 'Controller "duplicate" already exists' } } };
          }}
        >
          {(form) => (
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
          )}
        </FormDialog>
      );
    }
    return <Demo />;
  },
};

export const Destructive: StoryObj = {
  name: 'Destructive (delete confirmation)',
  render: () => {
    function Demo() {
      const [open, setOpen] = useState(false);
      const schema = z.object({
        confirmation: z.string().refine((v) => v === 'switch-core-01', {
          message: 'Type the device name to confirm',
        }),
      });
      return (
        <>
          <Button variant="destructive" onClick={() => setOpen(true)}>Delete switch…</Button>
          <FormDialog
            open={open}
            onOpenChange={setOpen}
            title="Delete switch-core-01?"
            description="This action cannot be undone. The device will be removed from inventory."
            schema={schema}
            defaultValues={{ confirmation: '' }}
            submitLabel="Delete forever"
            destructive
            onSubmit={async () => {
              await new Promise((r) => setTimeout(r, 600));
              alert('Deleted!');
            }}
          >
            {(form) => (
              <FormField
                control={form.control}
                name="confirmation"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Type "switch-core-01" to confirm</FormLabel>
                    <FormControl><Input placeholder="switch-core-01" {...field} /></FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}
          </FormDialog>
        </>
      );
    }
    return <Demo />;
  },
};
