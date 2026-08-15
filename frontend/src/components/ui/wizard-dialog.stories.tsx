// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { Meta, StoryObj } from '@storybook/react-vite';
import { useState } from 'react';
import { z } from 'zod';
import { WizardDialog } from './wizard-dialog';
import { FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from './form';
import { Input } from './input';
import { Button } from './button';

const meta: Meta<typeof WizardDialog> = {
  title: 'Primitives/WizardDialog',
  component: WizardDialog,
  parameters: {
    layout: 'centered',
    docs: {
      description: {
        component:
          'Multi-step form dialog. Sibling to FormDialog. Each step declares its own field set + optional async validate hook (e.g. test connection). Stepper UI at top, Back/Next/Submit footer. All field state preserved across step navigation (steps render hidden when inactive, not unmounted). Use for create wizards with 3+ logical steps; for single forms, use FormDialog.',
      },
    },
  },
};

export default meta;

// ── Demo schema: a 3-step "create integration" wizard ──

const integrationSchema = z.object({
  // Step 1: Type
  type: z.enum(['slack', 'webhook', 'email']),
  // Step 2: Config
  name: z.string().min(1, 'Name is required').max(40),
  endpoint: z.string().url('Must be a valid URL'),
  // Step 3: Test (no fields, just validates)
  enabled: z.boolean(),
});
type IntegrationForm = z.infer<typeof integrationSchema>;

export const ThreeStepWizard: StoryObj = {
  name: 'Create wizard (3 steps)',
  render: () => {
    function Demo() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <Button onClick={() => setOpen(true)}>Add integration…</Button>
          <WizardDialog<IntegrationForm>
            open={open}
            onOpenChange={setOpen}
            title="New integration"
            description="Set up a new notification integration in 3 steps"
            schema={integrationSchema}
            defaultValues={{ type: 'slack', name: '', endpoint: '', enabled: true }}
            steps={[
              {
                id: 'type',
                label: 'Choose type',
                fields: ['type'],
                content: (form) => (
                  <FormField
                    control={form.control}
                    name="type"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Integration type</FormLabel>
                        <FormControl>
                          <select
                            className="block w-full rounded border px-3 py-2 text-sm bg-background"
                            {...field}
                          >
                            <option value="slack">Slack webhook</option>
                            <option value="webhook">Generic webhook</option>
                            <option value="email">Email (SMTP)</option>
                          </select>
                        </FormControl>
                        <FormDescription>Pick the channel this integration will deliver to.</FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                ),
              },
              {
                id: 'config',
                label: 'Configure',
                fields: ['name', 'endpoint'],
                content: (form) => (
                  <>
                    <FormField
                      control={form.control}
                      name="name"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Display name</FormLabel>
                          <FormControl><Input placeholder="e.g. Alerts → #ops" {...field} /></FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                    <FormField
                      control={form.control}
                      name="endpoint"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Endpoint URL</FormLabel>
                          <FormControl><Input placeholder="https://hooks.slack.com/services/..." {...field} /></FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </>
                ),
              },
              {
                id: 'review',
                label: 'Review',
                fields: ['enabled'],
                content: (form) => (
                  <div className="space-y-3 text-sm">
                    <p className="text-muted-foreground">Review and confirm to create the integration.</p>
                    <dl className="grid grid-cols-2 gap-2 rounded border p-3">
                      <dt className="text-muted-foreground">Type</dt>
                      <dd className="font-medium">{form.watch('type')}</dd>
                      <dt className="text-muted-foreground">Name</dt>
                      <dd className="font-medium">{form.watch('name')}</dd>
                      <dt className="text-muted-foreground">Endpoint</dt>
                      <dd className="font-medium truncate">{form.watch('endpoint')}</dd>
                    </dl>
                  </div>
                ),
              },
            ]}
            submitLabel="Create integration"
            onSubmit={async (values) => {
              await new Promise((r) => setTimeout(r, 600));
              alert(`Created: ${JSON.stringify(values, null, 2)}`);
            }}
          />
        </>
      );
    }
    return <Demo />;
  },
};

export const WithAsyncValidation: StoryObj = {
  name: 'With async validate hook (test connection on step 2)',
  render: () => {
    function Demo() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <Button onClick={() => setOpen(true)}>Add controller…</Button>
          <WizardDialog
            open={open}
            onOpenChange={setOpen}
            title="Add controller"
            schema={z.object({
              host: z.string().url(),
              port: z.coerce.number().int().min(1).max(65535),
            })}
            defaultValues={{ host: 'https://controller.local', port: 443 }}
            steps={[
              {
                id: 'address',
                label: 'Address',
                fields: ['host', 'port'],
                content: (form) => (
                  <>
                    <FormField
                      control={form.control}
                      name="host"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Host URL</FormLabel>
                          <FormControl><Input {...field} /></FormControl>
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
                          <FormControl><Input type="number" {...field} /></FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </>
                ),
                // Async hook that simulates "test connection"
                validate: async (values) => {
                  await new Promise((r) => setTimeout(r, 800));
                  if (!values.host.includes('controller')) {
                    return 'Connection refused · host did not respond as a controller';
                  }
                  return undefined;
                },
              },
              {
                id: 'confirm',
                label: 'Confirm',
                fields: [],
                content: (form) => (
                  <div className="text-sm">
                    Connection verified. Add controller at <code className="bg-muted px-1.5 py-0.5 rounded text-xs">{form.watch('host')}:{form.watch('port')}</code>?
                  </div>
                ),
              },
            ]}
            submitLabel="Add controller"
            onSubmit={async () => {
              await new Promise((r) => setTimeout(r, 400));
            }}
          />
        </>
      );
    }
    return <Demo />;
  },
};

export const ServerErrorOnSubmit: StoryObj = {
  name: 'Server error on final submit',
  render: () => {
    function Demo() {
      const [open, setOpen] = useState(true);
      return (
        <WizardDialog
          open={open}
          onOpenChange={setOpen}
          title="Add user"
          schema={z.object({ email: z.string().email() })}
          defaultValues={{ email: 'duplicate@example.com' }}
          steps={[
            {
              id: 'email',
              label: 'Email',
              fields: ['email'],
              content: (form) => (
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
              ),
            },
            {
              id: 'review',
              label: 'Confirm',
              fields: [],
              content: () => <p className="text-sm">Click "Create" · it'll simulate a 409 conflict.</p>,
            },
          ]}
          onSubmit={async () => {
            await new Promise((r) => setTimeout(r, 400));
            throw { response: { data: { detail: 'Email "duplicate@example.com" is already registered' } } };
          }}
          submitLabel="Create user"
        />
      );
    }
    return <Demo />;
  },
};
