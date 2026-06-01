// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { describe, it, expect, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useForm } from 'react-hook-form';
import { Network, Trash2 } from 'lucide-react';
import { FormFieldArray, type FormFieldArrayRowHelpers } from '../form-field-array';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '../form';
import { Input } from '../input';
import { Button } from '../button';

interface AliasRow {
  name: string;
  cidr: string;
}

interface AliasForm {
  aliases: AliasRow[];
}

interface HarnessOpts {
  defaultValues?: AliasForm;
  minItems?: number;
  maxItems?: number;
  emptyState?: { title: string; description?: string };
  showCount?: boolean;
  label?: string;
  description?: string;
  /** Spy that receives the helpers passed to each row's render-prop. */
  onHelpers?: (h: FormFieldArrayRowHelpers, index: number) => void;
}

function Harness({
  defaultValues = { aliases: [] },
  minItems,
  maxItems,
  emptyState = { title: 'No aliases', description: 'Click Add to create one.' },
  showCount,
  label,
  description,
  onHelpers,
}: HarnessOpts) {
  const form = useForm<AliasForm>({ defaultValues });
  return (
    <Form {...form}>
      <FormFieldArray<AliasForm, 'aliases'>
        control={form.control}
        name="aliases"
        defaultItem={{ name: '', cidr: '' }}
        addLabel="Add alias"
        emptyState={{ icon: Network, ...emptyState }}
        minItems={minItems}
        maxItems={maxItems}
        showCount={showCount}
        label={label}
        description={description}
      >
        {(_item, index, helpers) => {
          onHelpers?.(helpers, index);
          return (
            <div className="flex gap-2 items-end" data-testid={`row-${index}`}>
              <FormField
                control={form.control}
                name={`aliases.${index}.name` as const}
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{`Name ${index}`}</FormLabel>
                    <FormControl>
                      <Input placeholder="alias name" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name={`aliases.${index}.cidr` as const}
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{`CIDR ${index}`}</FormLabel>
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
                onClick={() => helpers.remove()}
                disabled={helpers.removeDisabled}
                aria-label={`Remove alias ${index}`}
              >
                <Trash2 className="h-4 w-4" />
              </Button>
              <Button
                type="button"
                size="icon"
                onClick={() => helpers.move(Math.max(0, index - 1))}
                aria-label={`Move alias ${index} up`}
              >
                up
              </Button>
            </div>
          );
        }}
      </FormFieldArray>
    </Form>
  );
}

describe('FormFieldArray', () => {
  it('renders the empty state when there are no items', () => {
    render(<Harness />);
    expect(screen.getByText('No aliases')).toBeInTheDocument();
    expect(screen.getByText('Click Add to create one.')).toBeInTheDocument();
    // Add button is always present even when empty
    expect(screen.getByRole('button', { name: 'Add alias' })).toBeInTheDocument();
    // No rows
    expect(screen.queryByTestId('row-0')).not.toBeInTheDocument();
  });

  it('appends a row when Add is clicked', async () => {
    const user = userEvent.setup();
    render(<Harness />);
    await user.click(screen.getByRole('button', { name: 'Add alias' }));
    expect(screen.getByTestId('row-0')).toBeInTheDocument();
    // Empty state goes away
    expect(screen.queryByText('No aliases')).not.toBeInTheDocument();
  });

  it('removes a row when its Remove helper is invoked', async () => {
    const user = userEvent.setup();
    render(
      <Harness
        defaultValues={{
          aliases: [
            { name: 'a', cidr: '10.0.0.0/24' },
            { name: 'b', cidr: '10.0.1.0/24' },
          ],
        }}
      />,
    );
    expect(screen.getByTestId('row-0')).toBeInTheDocument();
    expect(screen.getByTestId('row-1')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Remove alias 0' }));
    // After removal, the second row collapses into index 0
    expect(screen.queryByTestId('row-1')).not.toBeInTheDocument();
    expect(screen.getByTestId('row-0')).toBeInTheDocument();
  });

  it('renders row indices that match the iteration order', async () => {
    render(
      <Harness
        defaultValues={{
          aliases: [
            { name: 'first', cidr: '' },
            { name: 'second', cidr: '' },
            { name: 'third', cidr: '' },
          ],
        }}
      />,
    );
    const row0 = screen.getByTestId('row-0');
    const row1 = screen.getByTestId('row-1');
    const row2 = screen.getByTestId('row-2');
    // Each row's first input should have the matching default value from its index
    expect(within(row0).getByPlaceholderText('alias name')).toHaveValue('first');
    expect(within(row1).getByPlaceholderText('alias name')).toHaveValue('second');
    expect(within(row2).getByPlaceholderText('alias name')).toHaveValue('third');
    // Labels include the index too
    expect(within(row0).getByText('Name 0')).toBeInTheDocument();
    expect(within(row1).getByText('Name 1')).toBeInTheDocument();
    expect(within(row2).getByText('Name 2')).toBeInTheDocument();
  });

  it('disables the Add button when at maxItems', async () => {
    const user = userEvent.setup();
    render(
      <Harness
        maxItems={2}
        defaultValues={{
          aliases: [
            { name: 'a', cidr: '' },
            { name: 'b', cidr: '' },
          ],
        }}
      />,
    );
    const addBtn = screen.getByRole('button', { name: 'Add alias' });
    expect(addBtn).toBeDisabled();
    // Click is a no-op (button disabled, but verify state didn't change)
    await user.click(addBtn);
    expect(screen.queryByTestId('row-2')).not.toBeInTheDocument();
  });

  it('disables Remove buttons when at minItems', () => {
    render(
      <Harness
        minItems={2}
        defaultValues={{
          aliases: [
            { name: 'a', cidr: '' },
            { name: 'b', cidr: '' },
          ],
        }}
      />,
    );
    expect(screen.getByRole('button', { name: 'Remove alias 0' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Remove alias 1' })).toBeDisabled();
  });

  it('re-enables Remove once count exceeds minItems', async () => {
    const user = userEvent.setup();
    render(
      <Harness
        minItems={1}
        defaultValues={{ aliases: [{ name: 'a', cidr: '' }] }}
      />,
    );
    expect(screen.getByRole('button', { name: 'Remove alias 0' })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Add alias' }));
    expect(screen.getByRole('button', { name: 'Remove alias 0' })).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Remove alias 1' })).toBeEnabled();
  });

  it('shows "N of MAX" count when maxItems is finite and items exist', () => {
    render(
      <Harness
        label="Aliases"
        maxItems={20}
        defaultValues={{
          aliases: [
            { name: 'a', cidr: '' },
            { name: 'b', cidr: '' },
            { name: 'c', cidr: '' },
          ],
        }}
      />,
    );
    expect(screen.getByLabelText('Item count')).toHaveTextContent('3 of 20');
  });

  it('shows "N items" count when maxItems is unbounded', () => {
    render(
      <Harness
        label="Aliases"
        defaultValues={{
          aliases: [
            { name: 'a', cidr: '' },
            { name: 'b', cidr: '' },
          ],
        }}
      />,
    );
    expect(screen.getByLabelText('Item count')).toHaveTextContent('2 items');
  });

  it('hides the count when showCount=false', () => {
    render(
      <Harness
        label="Aliases"
        showCount={false}
        defaultValues={{ aliases: [{ name: 'a', cidr: '' }] }}
      />,
    );
    expect(screen.queryByLabelText('Item count')).not.toBeInTheDocument();
  });

  it('passes helpers (remove, move, swap, isFirst, isLast, removeDisabled) to the render-prop', () => {
    const onHelpers = vi.fn();
    render(
      <Harness
        minItems={0}
        defaultValues={{
          aliases: [
            { name: 'a', cidr: '' },
            { name: 'b', cidr: '' },
            { name: 'c', cidr: '' },
          ],
        }}
        onHelpers={onHelpers}
      />,
    );
    // Render-prop fires once per row; collect the per-row helper objects
    const calls = onHelpers.mock.calls;
    const byIndex = new Map<number, FormFieldArrayRowHelpers>();
    for (const [helpers, index] of calls) {
      byIndex.set(index, helpers);
    }
    expect(byIndex.get(0)?.isFirst).toBe(true);
    expect(byIndex.get(0)?.isLast).toBe(false);
    expect(byIndex.get(2)?.isFirst).toBe(false);
    expect(byIndex.get(2)?.isLast).toBe(true);
    // Helper functions are present
    expect(typeof byIndex.get(0)?.remove).toBe('function');
    expect(typeof byIndex.get(0)?.move).toBe('function');
    expect(typeof byIndex.get(0)?.swap).toBe('function');
    expect(typeof byIndex.get(0)?.moveAbsolute).toBe('function');
    expect(typeof byIndex.get(0)?.swapAbsolute).toBe('function');
    // removeDisabled reflects minItems=0 vs count=3
    expect(byIndex.get(0)?.removeDisabled).toBe(false);
  });

  it('move helper reorders the rows', async () => {
    const user = userEvent.setup();
    render(
      <Harness
        defaultValues={{
          aliases: [
            { name: 'first', cidr: '' },
            { name: 'second', cidr: '' },
          ],
        }}
      />,
    );
    // Move row 1 up to index 0
    await user.click(screen.getByRole('button', { name: 'Move alias 1 up' }));
    const row0 = screen.getByTestId('row-0');
    const row1 = screen.getByTestId('row-1');
    expect(within(row0).getByPlaceholderText('alias name')).toHaveValue('second');
    expect(within(row1).getByPlaceholderText('alias name')).toHaveValue('first');
  });

  it('renders the optional label and description above the list', () => {
    render(
      <Harness
        label="Aliases"
        description="Named groups of hosts or networks."
      />,
    );
    expect(screen.getByText('Aliases')).toBeInTheDocument();
    expect(screen.getByText('Named groups of hosts or networks.')).toBeInTheDocument();
  });
});
