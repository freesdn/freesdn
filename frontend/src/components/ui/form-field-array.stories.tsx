// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import type { Meta, StoryObj } from '@storybook/react-vite';
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { z } from 'zod';
import { zodResolver } from '@hookform/resolvers/zod';
import { Network, Trash2, ArrowUp, ArrowDown, Mail } from 'lucide-react';
import { FormFieldArray } from './form-field-array';
import { FormDialog } from './form-dialog';
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from './form';
import { Input } from './input';
import { Button } from './button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from './select';

const meta: Meta<typeof FormFieldArray> = {
  title: 'Primitives/FormFieldArray',
  component: FormFieldArray,
  parameters: {
    layout: 'padded',
    docs: {
      description: {
        component:
          'Sub-form list primitive (one-to-many editor). Wraps react-hook-form `useFieldArray` with an Add button, empty state, item count, and per-row helpers (remove/move/swap). Use inside a `<FormDialog>` or any react-hook-form context.',
      },
    },
  },
};

export default meta;

// ── Story 1: Simple aliases list ──────────────────────────────────────────

const aliasesSchema = z.object({
  aliases: z.array(
    z.object({
      name: z.string().min(1, 'Name required'),
      cidr: z.string().min(1, 'CIDR required'),
    }),
  ),
});
type AliasesForm = z.infer<typeof aliasesSchema>;

export const SimpleList: StoryObj = {
  name: 'Simple aliases list',
  render: () => {
    function Demo() {
      const form = useForm<AliasesForm>({
        resolver: zodResolver(aliasesSchema),
        defaultValues: { aliases: [] },
      });
      return (
        <Form {...form}>
          <form
            onSubmit={form.handleSubmit((values) => alert(JSON.stringify(values, null, 2)))}
            className="space-y-4 max-w-xl"
          >
            <FormFieldArray<AliasesForm, 'aliases'>
              control={form.control}
              name="aliases"
              defaultItem={{ name: '', cidr: '' }}
              addLabel="Add alias"
              label="Aliases"
              description="Named groups of hosts or networks."
              maxItems={20}
              emptyState={{
                icon: Network,
                title: 'No aliases yet',
                description: 'Click Add to create your first alias.',
              }}
            >
              {(_item, index, { remove }) => (
                <div className="flex gap-2 items-end">
                  <FormField
                    control={form.control}
                    name={`aliases.${index}.name` as const}
                    render={({ field }) => (
                      <FormItem className="flex-1">
                        <FormLabel>Name</FormLabel>
                        <FormControl>
                          <Input placeholder="my_servers" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name={`aliases.${index}.cidr` as const}
                    render={({ field }) => (
                      <FormItem className="flex-1">
                        <FormLabel>CIDR</FormLabel>
                        <FormControl>
                          <Input placeholder="10.0.0.0/24" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    onClick={() => remove()}
                    aria-label={`Remove alias ${index + 1}`}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              )}
            </FormFieldArray>
            <Button type="submit">Save</Button>
          </form>
        </Form>
      );
    }
    return <Demo />;
  },
};

// ── Story 2: Complex (multiple field types per row) ────────────────────────

const recipientsSchema = z.object({
  recipients: z.array(
    z.object({
      email: z.string().email('Invalid email'),
      role: z.enum(['admin', 'editor', 'viewer']),
      notify: z.boolean(),
    }),
  ),
});
type RecipientsForm = z.infer<typeof recipientsSchema>;

export const ComplexRows: StoryObj = {
  name: 'Complex rows (multi-field + reorder)',
  render: () => {
    function Demo() {
      const form = useForm<RecipientsForm>({
        resolver: zodResolver(recipientsSchema),
        defaultValues: {
          recipients: [
            { email: 'alice@example.com', role: 'admin', notify: true },
            { email: 'bob@example.com', role: 'viewer', notify: false },
          ],
        },
      });
      return (
        <Form {...form}>
          <form
            onSubmit={form.handleSubmit((values) => alert(JSON.stringify(values, null, 2)))}
            className="space-y-4 max-w-2xl"
          >
            <FormFieldArray<RecipientsForm, 'recipients'>
              control={form.control}
              name="recipients"
              defaultItem={{ email: '', role: 'viewer', notify: true }}
              addLabel="Add recipient"
              label="Recipients"
              description="Reorder rows using the up/down handles."
              minItems={1}
              maxItems={10}
              rowClassName="border p-3"
              emptyState={{
                icon: Mail,
                title: 'No recipients',
              }}
            >
              {(_item, index, { remove, move, isFirst, isLast, removeDisabled }) => (
                <div className="flex gap-2 items-end">
                  <div className="flex flex-col gap-1">
                    <Button
                      type="button"
                      size="icon"
                      variant="ghost"
                      disabled={isFirst}
                      onClick={() => move(index - 1)}
                      aria-label="Move up"
                    >
                      <ArrowUp className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      type="button"
                      size="icon"
                      variant="ghost"
                      disabled={isLast}
                      onClick={() => move(index + 1)}
                      aria-label="Move down"
                    >
                      <ArrowDown className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                  <FormField
                    control={form.control}
                    name={`recipients.${index}.email` as const}
                    render={({ field }) => (
                      <FormItem className="flex-1">
                        <FormLabel>Email</FormLabel>
                        <FormControl>
                          <Input type="email" placeholder="user@example.com" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name={`recipients.${index}.role` as const}
                    render={({ field }) => (
                      <FormItem className="w-32">
                        <FormLabel>Role</FormLabel>
                        <Select value={field.value} onValueChange={field.onChange}>
                          <FormControl>
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            <SelectItem value="admin">Admin</SelectItem>
                            <SelectItem value="editor">Editor</SelectItem>
                            <SelectItem value="viewer">Viewer</SelectItem>
                          </SelectContent>
                        </Select>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    onClick={() => remove()}
                    disabled={removeDisabled}
                    aria-label="Remove recipient"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              )}
            </FormFieldArray>
            <Button type="submit">Save</Button>
          </form>
        </Form>
      );
    }
    return <Demo />;
  },
};

// ── Story 3: Min/Max enforcement demo ──────────────────────────────────────

const limitedSchema = z.object({
  servers: z.array(z.object({ host: z.string().min(1) })),
});
type LimitedForm = z.infer<typeof limitedSchema>;

export const MinMaxEnforcement: StoryObj = {
  name: 'Min/Max enforcement (1..3 items)',
  render: () => {
    function Demo() {
      const form = useForm<LimitedForm>({
        resolver: zodResolver(limitedSchema),
        defaultValues: { servers: [{ host: 'server-1.local' }] },
      });
      return (
        <Form {...form}>
          <form className="space-y-4 max-w-xl">
            <FormFieldArray<LimitedForm, 'servers'>
              control={form.control}
              name="servers"
              defaultItem={{ host: '' }}
              addLabel="Add server"
              label="DNS Servers"
              description="At least 1 required, maximum 3 allowed."
              minItems={1}
              maxItems={3}
              emptyState={{
                icon: Network,
                title: 'No servers configured',
              }}
            >
              {(_item, index, { remove, removeDisabled }) => (
                <div className="flex gap-2 items-end">
                  <FormField
                    control={form.control}
                    name={`servers.${index}.host` as const}
                    render={({ field }) => (
                      <FormItem className="flex-1">
                        <FormLabel>Host</FormLabel>
                        <FormControl>
                          <Input placeholder="dns.example.com" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    onClick={() => remove()}
                    disabled={removeDisabled}
                    aria-label="Remove server"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              )}
            </FormFieldArray>
          </form>
        </Form>
      );
    }
    return <Demo />;
  },
};

// ── Story 4: Inside a FormDialog ───────────────────────────────────────────

const dialogSchema = z.object({
  name: z.string().min(1, 'Name required'),
  members: z.array(
    z.object({ email: z.string().email('Invalid email') }),
  ).min(1, 'At least one member required'),
});
type DialogForm = z.infer<typeof dialogSchema>;

export const InsideFormDialog: StoryObj = {
  name: 'Inside a FormDialog',
  render: () => {
    function Demo() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <Button onClick={() => setOpen(true)}>Create team…</Button>
          <FormDialog<DialogForm>
            open={open}
            onOpenChange={setOpen}
            title="Create team"
            description="Add team members by email."
            schema={dialogSchema}
            defaultValues={{ name: '', members: [{ email: '' }] }}
            submitLabel="Create"
            onSubmit={async (values) => {
              await new Promise((r) => setTimeout(r, 400));
              alert(JSON.stringify(values, null, 2));
            }}
          >
            {(form) => (
              <>
                <FormField
                  control={form.control}
                  name="name"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Team name</FormLabel>
                      <FormControl>
                        <Input placeholder="Platform team" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormFieldArray<DialogForm, 'members'>
                  control={form.control}
                  name="members"
                  defaultItem={{ email: '' }}
                  addLabel="Add member"
                  label="Members"
                  minItems={1}
                  maxItems={50}
                  emptyState={{ icon: Mail, title: 'No members' }}
                >
                  {(_item, index, { remove, removeDisabled }) => (
                    <div className="flex gap-2 items-end">
                      <FormField
                        control={form.control}
                        name={`members.${index}.email` as const}
                        render={({ field }) => (
                          <FormItem className="flex-1">
                            <FormLabel className="sr-only">Email</FormLabel>
                            <FormControl>
                              <Input type="email" placeholder="user@example.com" {...field} />
                            </FormControl>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        onClick={() => remove()}
                        disabled={removeDisabled}
                        aria-label="Remove member"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  )}
                </FormFieldArray>
              </>
            )}
          </FormDialog>
        </>
      );
    }
    return <Demo />;
  },
};
