// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FormFieldArray · sub-form list primitive (one-to-many editor).
 *
 * Sibling to FormDialog and WizardDialog. Wraps react-hook-form's
 * `useFieldArray` with conventions for:
 *   - Add button (with custom label, disabled when at maxItems)
 *   - Empty state (icon + title + description) when items.length === 0
 *   - Per-row render-prop receiving (item, index, helpers)
 *   - Helpers expose `remove`, `move`, `swap` from useFieldArray
 *   - Per-row Remove disabled when at minItems
 *   - Optional item count badge (e.g. "3 of 20")
 *
 * Replaces ad-hoc `setItems((prev) => [...prev, empty])` / `prev.filter((_, i) => i !== idx)`
 * patterns found in SiteDetailPage subnets, HolidaySchedulePanel, PTZToursPanel,
 * GatewayResourceDialogs alias content, etc.
 *
 * Usage:
 *
 *   const schema = z.object({
 *     aliases: z.array(z.object({ name: z.string().min(1), cidr: z.string() })),
 *   });
 *
 *   <FormFieldArray
 *     control={form.control}
 *     name="aliases"
 *     defaultItem={{ name: '', cidr: '' }}
 *     addLabel="Add alias"
 *     emptyState={{ icon: Network, title: 'No aliases', description: 'Click Add to create one.' }}
 *     minItems={0}
 *     maxItems={20}
 *   >
 *     {(_item, index, { remove }) => (
 *       <div className="flex gap-2 items-end">
 *         <FormField name={`aliases.${index}.name`} control={form.control} render={...} />
 *         <FormField name={`aliases.${index}.cidr`} control={form.control} render={...} />
 *         <Button variant="ghost" size="icon" onClick={() => remove()} aria-label="Remove alias">
 *           <Trash2 className="h-4 w-4" />
 *         </Button>
 *       </div>
 *     )}
 *   </FormFieldArray>
 */
import { type ReactNode } from 'react';
import {
  useFieldArray,
  type ArrayPath,
  type Control,
  type FieldArray,
  type FieldArrayWithId,
  type FieldValues,
  type UseFieldArrayMove,
  type UseFieldArraySwap,
} from 'react-hook-form';
import { Plus, type LucideIcon } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Button } from './button';
import { cn } from '../../lib/utils';

/**
 * Helpers passed to each row via the children render-prop. These are scoped
 * to the row's index · `remove()` removes THIS row, `move(to)` moves THIS
 * row to a new index, `swap(other)` swaps THIS row with another.
 *
 * The unscoped `move` and `swap` (taking two indices) are also exposed for
 * advanced cases like drag-and-drop libraries that prefer absolute indices.
 */
export interface FormFieldArrayRowHelpers {
  /** Remove the row at this index */
  remove: () => void;
  /** Move this row to a new index (e.g. drag-and-drop reorder) */
  move: (toIndex: number) => void;
  /** Swap this row with another by absolute index */
  swap: (withIndex: number) => void;
  /** Underlying useFieldArray.move (absolute indices) for advanced use */
  moveAbsolute: UseFieldArrayMove;
  /** Underlying useFieldArray.swap (absolute indices) for advanced use */
  swapAbsolute: UseFieldArraySwap;
  /** True when this row is the first */
  isFirst: boolean;
  /** True when this row is the last */
  isLast: boolean;
  /** True when removing would drop below `minItems` */
  removeDisabled: boolean;
}

export interface FormFieldArrayEmptyState {
  /** Optional icon for the empty placeholder (lucide-react component) */
  icon?: LucideIcon;
  /** Required title shown in the empty state */
  title: string;
  /** Optional secondary description */
  description?: string;
}

export interface FormFieldArrayProps<
  TFieldValues extends FieldValues = FieldValues,
  TFieldArrayName extends ArrayPath<TFieldValues> = ArrayPath<TFieldValues>,
> {
  /** react-hook-form control (from `useForm()` / outer FormDialog) */
  control: Control<TFieldValues>;
  /** Field path (e.g. `"aliases"` or `"interfaces.0.subnets"`) */
  name: TFieldArrayName;
  /** Default shape used when the user clicks Add */
  defaultItem: FieldArray<TFieldValues, TFieldArrayName>;
  /**
   * Render-prop for each row. Receives the field with its stable `id`,
   * the row's index, and per-row helpers.
   *
   * Children inside this render-prop should reference fields via
   * `${name}.${index}.field` paths so react-hook-form tracks them inside
   * the array context.
   */
  children: (
    item: FieldArrayWithId<TFieldValues, TFieldArrayName, 'id'>,
    index: number,
    helpers: FormFieldArrayRowHelpers,
  ) => ReactNode;
  /** Add button label. Defaults to the localized "Add". */
  addLabel?: string;
  /** Optional empty-state placeholder shown when no items exist */
  emptyState?: FormFieldArrayEmptyState;
  /** Minimum number of items. Remove buttons disable at this count. Default 0. */
  minItems?: number;
  /** Maximum number of items. Add button disables at this count. Default Infinity. */
  maxItems?: number;
  /** Show "N of MAX" / "N items" count next to the Add button. Default true. */
  showCount?: boolean;
  /** Class applied to the outer wrapper */
  className?: string;
  /** Class applied to the row container `<div>` (around each render) */
  rowClassName?: string;
  /** Optional label rendered above the list (e.g. "Aliases") */
  label?: string;
  /** Optional description rendered under the label */
  description?: string;
}

export function FormFieldArray<
  TFieldValues extends FieldValues = FieldValues,
  TFieldArrayName extends ArrayPath<TFieldValues> = ArrayPath<TFieldValues>,
>({
  control,
  name,
  defaultItem,
  children,
  addLabel,
  emptyState,
  minItems = 0,
  maxItems = Number.POSITIVE_INFINITY,
  showCount = true,
  className,
  rowClassName,
  label,
  description,
}: FormFieldArrayProps<TFieldValues, TFieldArrayName>) {
  const { t } = useTranslation('common');
  const resolvedAddLabel = addLabel ?? t('FormFieldArray.actions.add');
  const { fields, append, remove, move, swap } = useFieldArray<
    TFieldValues,
    TFieldArrayName,
    'id'
  >({
    control,
    name,
  });

  const count = fields.length;
  const atMax = count >= maxItems;
  const removeDisabled = count <= minItems;

  const handleAdd = () => {
    if (atMax) return;
    // Cast: useFieldArray's append is typed for either a single item or an array.
    // We always append one · the union confuses TS without an explicit cast.
    append(defaultItem as never);
  };

  const showEmpty = count === 0 && !!emptyState;

  return (
    <div className={cn('space-y-3', className)}>
      {(label || description || showCount) && (
        <div className="flex items-start justify-between gap-2">
          <div className="space-y-0.5">
            {label && <div className="text-sm font-medium">{label}</div>}
            {description && (
              <div className="text-xs text-muted-foreground">{description}</div>
            )}
          </div>
          {showCount && count > 0 && (
            <span
              className="text-xs text-muted-foreground tabular-nums"
              aria-label={t('FormFieldArray.itemCount.ariaLabel')}
            >
              {Number.isFinite(maxItems)
                ? t('FormFieldArray.itemCount.ofMax', { n: count, max: maxItems })
                : t('FormFieldArray.itemCount.items', { n: count })}
            </span>
          )}
        </div>
      )}

      {showEmpty ? (
        <EmptyPlaceholder {...emptyState} />
      ) : (
        <div className="space-y-2">
          {fields.map((item, index) => {
            const helpers: FormFieldArrayRowHelpers = {
              remove: () => remove(index),
              move: (to) => move(index, to),
              swap: (withIndex) => swap(index, withIndex),
              moveAbsolute: move,
              swapAbsolute: swap,
              isFirst: index === 0,
              isLast: index === fields.length - 1,
              removeDisabled,
            };
            return (
              <div key={item.id} className={cn('rounded-md', rowClassName)}>
                {children(item, index, helpers)}
              </div>
            );
          })}
        </div>
      )}

      <div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={handleAdd}
          disabled={atMax}
          aria-label={resolvedAddLabel}
        >
          <Plus className="h-4 w-4 mr-1" />
          {resolvedAddLabel}
        </Button>
      </div>
    </div>
  );
}

// ── Internal empty placeholder ─────────────────────────────────────────────

function EmptyPlaceholder({ icon: Icon, title, description }: FormFieldArrayEmptyState) {
  return (
    <div
      className="flex flex-col items-center justify-center rounded-md border border-dashed py-6 px-4 text-center"
      role="status"
    >
      {Icon && (
        <div className="flex h-10 w-10 items-center justify-center rounded-full bg-muted mb-2">
          <Icon className="h-5 w-5 text-muted-foreground" aria-hidden />
        </div>
      )}
      <p className="text-sm font-medium">{title}</p>
      {description && (
        <p className="text-xs text-muted-foreground mt-1">{description}</p>
      )}
    </div>
  );
}
