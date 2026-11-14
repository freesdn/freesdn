// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN Design System - Unified Data Table Component
 * 
 * Enterprise-grade data table with consistent styling across all pages.
 * Features:
 * - Row selection with checkbox (select current page or all pages)
 * - Sorting by columns
 * - Pagination with 25 items default
 * - Global search/filtering
 * - Bulk action support
 * - Loading states
 * - Empty states
 */

import React, { useState, useMemo, ReactNode, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import {
  useTable,
  tableFeatures,
  columnFilteringFeature,
  globalFilteringFeature,
  columnVisibilityFeature,
  rowPaginationFeature,
  rowSelectionFeature,
  rowSortingFeature,
  createFilteredRowModel,
  createPaginatedRowModel,
  createSortedRowModel,
  filterFns,
  sortFns,
  flexRender,
  ColumnDef,
  SortingState,
  ColumnFiltersState,
  RowSelectionState,
  Column,
  Row,
  type RowData,
  type ReactTable,
} from '@tanstack/react-table';
import {
  ChevronUp,
  ChevronDown,
  ChevronsUpDown,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Columns3,
  Search,
} from 'lucide-react';
import { Card, CardContent } from './card';
import { Button } from './button';
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from './dropdown-menu';
import { EmptyState, ErrorState, InlineErrorBanner } from './empty-state';
import { getApiErrorMessage } from '@/lib/api/errors';
import { Skeleton } from './skeleton';
import { SearchBar } from './search-bar';
import { cn } from '../../lib/utils';

// TanStack v9 registers features explicitly. Keep the feature graph stable so
// sorting, filtering, selection, and pagination share one reactive table store.
const dataTableFeatures = tableFeatures({
  columnFilteringFeature,
  globalFilteringFeature,
  columnVisibilityFeature,
  rowPaginationFeature,
  rowSelectionFeature,
  rowSortingFeature,
  filteredRowModel: createFilteredRowModel(),
  paginatedRowModel: createPaginatedRowModel(),
  sortedRowModel: createSortedRowModel(),
  filterFns,
  sortFns,
});
type DataTableFeatures = typeof dataTableFeatures;

// ============================================================================
// Types
// ============================================================================

export interface DataTableColumn<T> {
  id: string;
  header: string | ReactNode;
  accessorKey?: keyof T;
  accessorFn?: (row: T) => unknown;
  cell?: (row: T) => ReactNode;
  /**
   * Set false to turn sorting off. A column can only sort when it has an
   * `accessorKey` or `accessorFn` (the value to compare); without one it
   * renders a plain header whatever this says.
   */
  sortable?: boolean;
  /** Applied to every body cell of the column. */
  className?: string;
  /** Applied to the header cell. */
  headerClassName?: string;
  /**
   * With `enableColumnVisibility`, whether the user may hide this column.
   * Defaults to true for data columns; the selection column is never hideable.
   */
  hideable?: boolean;
  /** With `enableColumnVisibility`, start hidden until the user shows it. */
  defaultHidden?: boolean;
  /** Plain-text name for the column picker when `header` is not a string. */
  menuLabel?: string;
  /**
   * Horizontal alignment of the header and every cell. Right-align numeric
   * columns (counts, ports, throughput, uptime) so digits line up; the table
   * already renders figures at fixed width.
   */
  align?: 'left' | 'center' | 'right';
}

export interface SelectionInfo<T> {
  selectedRows: T[];
  selectedCount: number;
  totalCount: number;
  isAllPageSelected: boolean;
  isAllSelected: boolean;
  selectAll: () => void;
  clearSelection: () => void;
}

export interface DataTableProps<T> {
  /** Data array to display */
  data: T[];
  /** Column definitions */
  columns: DataTableColumn<T>[];
  /** Loading state */
  isLoading?: boolean;
  /** Enable row selection */
  selectable?: boolean;
  /** Callback when selection changes - includes full selection info for BulkActionsBar */
  onSelectionChange?: (selectedRows: T[], selectionInfo?: SelectionInfo<T>) => void;
  /** Search placeholder text */
  searchPlaceholder?: string;
  /** Enable search/filtering */
  searchable?: boolean;
  /** Custom empty state component */
  emptyState?: ReactNode;
  /** Custom loading skeleton rows count */
  skeletonRows?: number;
  /** Row key accessor */
  getRowId?: (row: T) => string;
  /**
   * The row's name for its selection checkbox ("Select core-sw-1"). Without
   * it every checkbox is announced as just "Select row".
   */
  getRowLabel?: (row: T) => string;
  /** Row click handler */
  onRowClick?: (row: T) => void;
  /** Custom class for the table container */
  className?: string;
  /** Enable pagination */
  paginated?: boolean;
  /** Page size options */
  pageSizeOptions?: number[];
  /** Default page size */
  defaultPageSize?: number;
  /** Item name for display (e.g., "devices", "users") */
  itemName?: string;
  /** Total count for server-side pagination */
  totalCount?: number;
  /**
   * Embedded mode · removes the internal Card wrapper so the table renders
   * directly inside an outer Card without double-nesting.  Search bar gets
   * horizontal padding to align with CardHeader.
   */
  embedded?: boolean;
  /**
   * The parent's copy of the selection, for pages that clear or prune it
   * themselves (a BulkActionsBar "clear", a finished bulk action). Without
   * this, clearing the parent's array hid the bar but left every checkbox
   * ticked, and the next tick re-announced the stale rows.
   */
  selectedRows?: T[];
  /**
   * Show a column picker in the header row. Persisted per browser under
   * `columnVisibilityKey` when one is given.
   */
  enableColumnVisibility?: boolean;
  /** localStorage key for the column picker's choice (e.g. 'devices'). */
  columnVisibilityKey?: string;
  /**
   * Row density. `compact` suits long inventories (switch ports, access
   * points, clients) where operators scan many rows at once.
   */
  density?: 'comfortable' | 'compact';
  /**
   * The query error, if loading failed. With no rows it replaces the table
   * with an error state carrying the server's message; with rows (stale data
   * from a failed refetch) it shows a banner above them instead.
   */
  error?: unknown;
  /** Retry handler for the error state (usually the query's refetch). */
  onRetry?: () => void;
}

// ============================================================================
// Styled Checkbox Component (slick dark style, easier to see when checked)
// ============================================================================

interface TableCheckboxProps {
  checked: boolean | 'indeterminate';
  onChange: (checked: boolean) => void;
  disabled?: boolean;
  'aria-label'?: string;
}

function TableCheckbox({ checked, onChange, disabled, 'aria-label': ariaLabel }: TableCheckboxProps) {
  return (
    <input
      type="checkbox"
      checked={checked === true}
      ref={(el) => {
        if (el) el.indeterminate = checked === 'indeterminate';
      }}
      onChange={(e) => {
        e.stopPropagation();
        if (!disabled) onChange(e.target.checked);
      }}
      onClick={(e) => e.stopPropagation()}
      disabled={disabled}
      aria-label={ariaLabel}
      className={cn(
        'h-4 w-4 rounded border-border bg-transparent cursor-pointer accent-primary',
        // A 20%-opacity ring on :focus was close to invisible and also showed
        // on mouse clicks; use the standard keyboard ring.
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background',
        disabled && 'opacity-50 cursor-not-allowed'
      )}
    />
  );
}

// ============================================================================
// Sort Button Component
// ============================================================================

interface SortButtonProps<T extends RowData> {
  column: Column<DataTableFeatures, T, unknown>;
  children: ReactNode;
  align?: 'left' | 'center' | 'right';
}

function SortButton<T extends RowData>({ column, children, align = 'left' }: SortButtonProps<T>) {
  const sorted = column.getIsSorted();
  
  return (
    <Button
      variant="ghost"
      size="sm"
      className={cn(
        'h-8 font-medium text-muted-foreground hover:text-foreground',
        // Pull the button's padding out so its label lines up with the cells.
        align === 'right' ? '-mr-3' : align === 'center' ? '' : '-ml-3',
      )}
      onClick={() => column.toggleSorting(sorted === 'asc')}
    >
      {children}
      {sorted === 'asc' ? (
        <ChevronUp className="ml-1 h-4 w-4" />
      ) : sorted === 'desc' ? (
        <ChevronDown className="ml-1 h-4 w-4" />
      ) : (
        <ChevronsUpDown className="ml-1 h-4 w-4 opacity-40" />
      )}
    </Button>
  );
}

// ============================================================================
// Loading Skeleton Component
// ============================================================================

function TableSkeleton({
  rows = 10,
  columns = 6,
  embedded = false,
  label,
}: {
  rows?: number;
  columns?: number;
  /** Inside an outer Card already: render without a Card of its own. */
  embedded?: boolean;
  /** Announced to screen readers while loading. */
  label?: string;
}) {
  // One placeholder per column (capped), so the skeleton has the table's shape.
  const cells = Math.min(Math.max(columns, 2), 8);
  const body = (
    <div className="space-y-0" role="status" aria-busy="true" aria-live="polite">
      {label && <span className="sr-only">{label}</span>}
      {/* Header skeleton */}
      <div className="flex items-center gap-4 h-12 px-4 border-b border-border/50 bg-muted/30">
        {Array.from({ length: cells }).map((_, i) => (
          <Skeleton key={i} className={cn('h-4 flex-1', i === 0 ? 'max-w-[140px]' : 'max-w-[100px]')} />
        ))}
      </div>
      {/* Row skeletons */}
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-4 px-4 py-3 border-b border-border/30 last:border-0">
          {Array.from({ length: cells }).map((__, j) => (
            <Skeleton
              key={j}
              className={cn('h-4 flex-1', j === 0 ? 'max-w-[180px]' : 'max-w-[110px]')}
            />
          ))}
        </div>
      ))}
    </div>
  );
  if (embedded) return body;
  return (
    <Card>
      <CardContent className="p-0">{body}</CardContent>
    </Card>
  );
}

// ============================================================================
// Default Empty State Component
// ============================================================================

function DefaultEmptyState({ searchQuery, itemName = 'items' }: { searchQuery?: string; itemName?: string }) {
  const { t } = useTranslation('common');
  return (
    <EmptyState
      icon={Search}
      title={t('DataTable.empty.title', { itemName })}
      description={
        searchQuery
          ? t('DataTable.empty.searchDescription', { itemName, searchQuery })
          : t('DataTable.empty.description', { itemName })
      }
    />
  );
}

// ============================================================================
// Pagination Component
// ============================================================================

interface PaginationProps<T extends RowData> {
  table: ReactTable<DataTableFeatures, T>;
  pageSizeOptions: number[];
  itemName: string;
  totalCount?: number;
}

function Pagination<T extends RowData>({ table, pageSizeOptions, itemName, totalCount }: PaginationProps<T>) {
  const { t } = useTranslation('common');
  const { pageIndex, pageSize } = table.state.pagination;
  const totalItems = totalCount ?? table.getFilteredRowModel().rows.length;
  const startItem = totalItems > 0 ? pageIndex * pageSize + 1 : 0;
  const endItem = Math.min((pageIndex + 1) * pageSize, totalItems);
  const pageCount = table.getPageCount() || 1;
  
  return (
    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 px-3 sm:px-4 py-3 border-t border-border/50">
      {/* Left side - showing count */}
      <p className="text-xs sm:text-sm text-muted-foreground">
        {t('DataTable.pagination.showing', { startItem, endItem, totalItems, itemName })}
      </p>

      {/* Right side - page navigation */}
      <div className="flex items-center justify-between sm:justify-end gap-2 sm:gap-4 flex-wrap">
        {/* Page size selector */}
        <div className="flex items-center gap-2">
          <select
            value={pageSize}
            onChange={(e) => table.setPageSize(Number(e.target.value))}
            aria-label={t('DataTable.pagination.rowsPerPage')}
            className="h-8 rounded-md border border-input bg-background px-2 text-sm text-foreground tabular-nums focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            {pageSizeOptions.map((size) => (
              <option key={size} value={size}>
                {size}
              </option>
            ))}
          </select>
        </div>
        
        {/* Page info and navigation */}
        <div className="flex items-center gap-2">
          <span className="text-sm text-muted-foreground whitespace-nowrap">
            {t('DataTable.pagination.pageOf', { current: pageIndex + 1, total: pageCount })}
          </span>
          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() => table.setPageIndex(0)}
              disabled={!table.getCanPreviousPage()}
              aria-label={t('DataTable.pagination.firstPage')}
            >
              <ChevronsLeft className="h-4 w-4" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() => table.previousPage()}
              disabled={!table.getCanPreviousPage()}
              aria-label={t('DataTable.pagination.previousPage')}
            >
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() => table.nextPage()}
              disabled={!table.getCanNextPage()}
              aria-label={t('DataTable.pagination.nextPage')}
            >
              <ChevronRight className="h-4 w-4" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() => table.setPageIndex(table.getPageCount() - 1)}
              disabled={!table.getCanNextPage()}
              aria-label={t('DataTable.pagination.lastPage')}
            >
              <ChevronsRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Column visibility persistence
// ============================================================================

const VISIBILITY_PREFIX = 'freesdn-table-columns:';

function readStoredVisibility(key: string | undefined): Record<string, boolean> | null {
  if (!key) return null;
  try {
    const raw = window.localStorage.getItem(VISIBILITY_PREFIX + key);
    const parsed: unknown = raw ? JSON.parse(raw) : null;
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, boolean>) : null;
  } catch {
    return null;
  }
}

function writeStoredVisibility(key: string | undefined, value: Record<string, boolean>) {
  if (!key) return;
  try {
    window.localStorage.setItem(VISIBILITY_PREFIX + key, JSON.stringify(value));
  } catch {
    // Private mode or blocked storage: the choice simply does not persist.
  }
}

const ALIGN_CLASS = { left: 'text-left', center: 'text-center', right: 'text-right' } as const;

// Controls inside a clickable row act on their own: a click on one must not
// also open the row.
const ROW_CONTROL = 'button, a[href], input, select, textarea, label, [role="menuitem"], [role="menu"], [role="checkbox"], [role="switch"], [data-row-click-ignore]';

/**
 * Whether a click on a row should open it. React bubbles events from a
 * portal (an open dropdown menu, a dialog) through the component tree, so a
 * menu item chosen from a row's actions menu reached the row's onClick and
 * navigated away too; so did the menu's trigger button. Only a click on the
 * row's own content opens it.
 */
function isRowOpeningClick(event: React.MouseEvent<HTMLElement>): boolean {
  const target = event.target;
  if (!(target instanceof Element) || !event.currentTarget.contains(target)) return false;
  const control = target.closest(ROW_CONTROL);
  return !control || !event.currentTarget.contains(control);
}

function ariaSort(sorted: false | 'asc' | 'desc'): 'ascending' | 'descending' | 'none' {
  return sorted === 'asc' ? 'ascending' : sorted === 'desc' ? 'descending' : 'none';
}

// ============================================================================
// Main DataTable Component
// ============================================================================

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function DataTable<T extends Record<string, any>>({
  data,
  columns: columnDefs,
  isLoading = false,
  selectable = false,
  onSelectionChange,
  searchPlaceholder,
  searchable = true,
  emptyState,
  skeletonRows = 10,
  getRowId = (row) => row.id,
  getRowLabel,
  onRowClick,
  className,
  paginated = true,
  pageSizeOptions = [10, 25, 50, 100],
  defaultPageSize = 25,
  itemName: itemNameProp = 'items',
  totalCount,
  embedded = false,
  selectedRows,
  enableColumnVisibility = false,
  columnVisibilityKey,
  density = 'comfortable',
  error,
  onRetry,
}: DataTableProps<T>) {
  const { t } = useTranslation('common');
  const resolvedSearchPlaceholder = searchPlaceholder ?? t('DataTable.searchPlaceholder');
  const [sorting, setSorting] = useState<SortingState>([]);
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [globalFilter, setGlobalFilter] = useState('');
  const defaultVisibility = useMemo(() => {
    const hidden: Record<string, boolean> = {};
    for (const col of columnDefs) if (col.defaultHidden) hidden[col.id] = false;
    return hidden;
  }, [columnDefs]);
  const [columnVisibility, setColumnVisibility] = useState<Record<string, boolean>>(() =>
    enableColumnVisibility
      ? { ...defaultVisibility, ...(readStoredVisibility(columnVisibilityKey) ?? {}) }
      : {},
  );
  const columnMeta = useMemo(() => new Map(columnDefs.map((c) => [c.id, c])), [columnDefs]);

  // Convert our column definitions to TanStack Table format
  const columns = useMemo<ColumnDef<DataTableFeatures, T>[]>(() => {
    const cols: ColumnDef<DataTableFeatures, T>[] = [];

    // Add selection column if selectable
    if (selectable) {
      cols.push({
        id: 'select',
        header: ({ table }) => {
          const isAllPageSelected = table.getIsAllPageRowsSelected();
          const isSomeSelected = table.getIsSomePageRowsSelected();

          return (
            <TableCheckbox
              checked={isAllPageSelected ? true : isSomeSelected ? 'indeterminate' : false}
              onChange={(checked) => table.toggleAllPageRowsSelected(checked)}
              aria-label={t('DataTable.selectAllRows')}
            />
          );
        },
        cell: ({ row }) => {
          const name = getRowLabel?.(row.original);
          return (
            <TableCheckbox
              checked={row.getIsSelected()}
              onChange={(checked) => row.toggleSelected(checked)}
              aria-label={name ? t('DataTable.selectRowNamed', { name }) : t('DataTable.selectRow')}
            />
          );
        },
        enableSorting: false,
        enableHiding: false,
      });
    }

    // Add data columns · only include accessorKey/accessorFn/cell when defined
    // to avoid overriding TanStack Table defaults with undefined
    columnDefs.forEach((col) => {
      // A column sorts only when it has a value to sort by. One with just a
      // `cell` renderer (actions, badges built from several fields) used to
      // get a sort button that did nothing when clicked; TanStack itself
      // reports such a column as unsortable, so ask it.
      const canSort = col.sortable !== false && (col.accessorKey != null || col.accessorFn != null);
      const colDef: ColumnDef<DataTableFeatures, T> = {
        id: col.id,
        header: ({ column }: { column: Column<DataTableFeatures, T, unknown> }) =>
          column.getCanSort()
            ? <SortButton column={column} align={col.align}>{col.header}</SortButton>
            : <span className="font-medium text-muted-foreground text-xs">{col.header}</span>,
        enableSorting: canSort,
      };
      if (col.accessorKey != null) (colDef as ColumnDef<DataTableFeatures, T> & { accessorKey: string }).accessorKey = col.accessorKey as string;
      if (col.accessorFn) (colDef as ColumnDef<DataTableFeatures, T> & { accessorFn: (row: T) => unknown }).accessorFn = col.accessorFn;
      if (col.cell) colDef.cell = ({ row }: { row: Row<DataTableFeatures, T> }) => col.cell!(row.original);
      cols.push(colDef);
    });

    return cols;
  }, [columnDefs, selectable, t, getRowLabel]);

  const table = useTable({
    features: dataTableFeatures,
    data,
    columns,
    state: {
      sorting,
      columnFilters,
      rowSelection,
      globalFilter,
      columnVisibility,
    },
    enableRowSelection: selectable,
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    onRowSelectionChange: setRowSelection,
    onGlobalFilterChange: setGlobalFilter,
    onColumnVisibilityChange: setColumnVisibility,
    manualPagination: !paginated,
    getRowId: (row) => getRowId(row),
    initialState: {
      pagination: {
        pageIndex: 0,
        pageSize: defaultPageSize,
      },
    },
  });

  // Notify parent of selection changes - use useRef to avoid infinite loop
  const prevSelectionRef = React.useRef<string>('');
  
  useEffect(() => {
    if (onSelectionChange) {
      const selectionKey = Object.keys(rowSelection).filter(k => rowSelection[k]).sort().join(',');
      if (selectionKey !== prevSelectionRef.current) {
        prevSelectionRef.current = selectionKey;
        const selectedRows = table.getFilteredSelectedRowModel().rows.map(row => row.original);
        const allRowsCount = table.getFilteredRowModel().rows.length;
        const selectedCount = selectedRows.length;
        const isAllPageSelected = table.getIsAllPageRowsSelected();
        const isAllSelected = selectedCount === allRowsCount && allRowsCount > 0;
        
        const selectionInfo: SelectionInfo<T> = {
          selectedRows,
          selectedCount,
          totalCount: allRowsCount,
          isAllPageSelected,
          isAllSelected,
          selectAll: () => table.toggleAllRowsSelected(true),
          clearSelection: () => table.resetRowSelection(),
        };
        
        onSelectionChange(selectedRows, selectionInfo);
      }
    }
  }, [rowSelection, onSelectionChange, table]);

  // Follow the parent's selection when it is passed in (see `selectedRows`).
  const selectedRowKey = selectedRows?.map((row) => getRowId(row)).sort().join(',');
  useEffect(() => {
    if (selectedRowKey === undefined) return;
    const current = Object.keys(rowSelection).filter((k) => rowSelection[k]).sort().join(',');
    if (selectedRowKey === current) return;
    // Pre-seed the change-notification key so this sync is not echoed back.
    prevSelectionRef.current = selectedRowKey;
    setRowSelection(
      Object.fromEntries(selectedRowKey ? selectedRowKey.split(',').map((id) => [id, true]) : []),
    );
    // Only the parent's selection drives this; rowSelection is read, not watched.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedRowKey]);

  useEffect(() => {
    if (enableColumnVisibility) writeStoredVisibility(columnVisibilityKey, columnVisibility);
  }, [enableColumnVisibility, columnVisibilityKey, columnVisibility]);

  const hideableColumns = enableColumnVisibility
    ? table.getAllLeafColumns().filter((col) => {
        const meta = columnMeta.get(col.id);
        if (!meta || meta.hideable === false) return false;
        return typeof meta.header === 'string' ? meta.header.trim() !== '' : !!meta.menuLabel;
      })
    : [];
  const visibleDataColumns = table.getVisibleLeafColumns().filter((c) => c.id !== 'select').length;

  const columnMenu = hideableColumns.length > 0 && (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8 text-muted-foreground hover:text-foreground"
          aria-label={t('DataTable.columns.button')}
          title={t('DataTable.columns.button')}
        >
          <Columns3 className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuLabel>{t('DataTable.columns.title')}</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {hideableColumns.map((col) => {
          const meta = columnMeta.get(col.id);
          const label = typeof meta?.header === 'string' ? meta.header : (meta?.menuLabel ?? col.id);
          const visible = col.getIsVisible();
          return (
            <DropdownMenuCheckboxItem
              key={col.id}
              checked={visible}
              // Never let the last data column go: an empty table reads as no data.
              disabled={visible && visibleDataColumns <= 1}
              onCheckedChange={(checked) => col.toggleVisibility(!!checked)}
              onSelect={(e) => e.preventDefault()}
            >
              {label}
            </DropdownMenuCheckboxItem>
          );
        })}
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => setColumnVisibility(defaultVisibility)}>
          {t('DataTable.columns.reset')}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
  const visibleLeaves = table.getVisibleLeafColumns();
  const lastColumnId = visibleLeaves[visibleLeaves.length - 1]?.id;
  const menuInActionsHeader = !!columnMenu && lastColumnId === 'actions';
  const extraMenuColumn = !!columnMenu && !menuInActionsHeader;

  // Show loading skeleton
  if (isLoading) {
    // Embedded tables already sit in the page's Card: a second Card here
    // drew a box inside the box until the data arrived.
    return (
      <TableSkeleton
        rows={skeletonRows}
        columns={columns.length}
        embedded={embedded}
        label={t('DataTable.loading', { itemName: itemNameProp })}
      />
    );
  }

  const errorMessage = error ? getApiErrorMessage(error) : null;
  const alignClass = (columnId: string) => {
    const align = columnMeta.get(columnId)?.align;
    return align ? ALIGN_CLASS[align] : undefined;
  };

  // Shared table + pagination markup
  const tableContent = (
    <>
      {errorMessage && data.length > 0 && (
        <InlineErrorBanner onRetry={onRetry} className="m-3">
          {errorMessage}
        </InlineErrorBanner>
      )}
      {errorMessage && data.length === 0 ? (
        <ErrorState message={errorMessage} onRetry={onRetry} />
      ) : data.length === 0 && !globalFilter ? (
        emptyState || <DefaultEmptyState searchQuery={globalFilter} itemName={itemNameProp} />
      ) : table.getRowModel().rows.length === 0 ? (
        <DefaultEmptyState searchQuery={globalFilter} itemName={itemNameProp} />
      ) : (
        <>
          {/* relative: an absolutely positioned child (a screen-reader-only
              header label) is placed inside the scroller instead of at the
              far right of the page, where it widened the whole document. */}
          <div className="relative overflow-x-auto" data-testid="data-table-scroller">
            {/* tabular-nums: digits take equal width, so counts, IPs, MACs and
                rates line up down a column instead of jittering. */}
            <table className="w-full tabular-nums" aria-label={t('DataTable.tableAriaLabel', { itemName: itemNameProp })}>
              <thead>
                <tr className="border-b border-border/50">
                  {table.getHeaderGroups().map((headerGroup) =>
                    headerGroup.headers.map((header) => (
                      <th
                        key={header.id}
                        scope="col"
                        aria-sort={
                          header.column.getCanSort() ? ariaSort(header.column.getIsSorted()) : undefined
                        }
                        className={cn(
                          'text-left align-middle text-sm font-medium text-muted-foreground whitespace-nowrap',
                          density === 'compact' ? 'px-3' : 'px-4',
                          density === 'compact' ? 'h-10' : 'h-12',
                          header.id === 'select' && 'w-12',
                          header.id === 'actions' && 'text-right',
                          alignClass(header.id),
                          columnMeta.get(header.id)?.headerClassName
                        )}
                      >
                        {header.isPlaceholder ? null : (
                          <>
                            {flexRender(header.column.columnDef.header, header.getContext())}
                            {menuInActionsHeader && header.id === 'actions' && columnMenu}
                          </>
                        )}
                      </th>
                    ))
                  )}
                  {extraMenuColumn && (
                    <th scope="col" className="h-12 w-10 px-2 text-right align-middle">
                      {columnMenu}
                    </th>
                  )}
                </tr>
              </thead>
              <tbody>
                {table.getRowModel().rows.map((row) => (
                  <tr
                    key={row.id}
                    onClick={(e) => {
                      if (onRowClick && isRowOpeningClick(e)) onRowClick(row.original);
                    }}
                    // Clickable rows open from the keyboard too, not only
                    // with a mouse.
                    tabIndex={onRowClick ? 0 : undefined}
                    onKeyDown={
                      onRowClick
                        ? (e) => {
                            if (e.target !== e.currentTarget) return;
                            if (e.key === 'Enter' || e.key === ' ') {
                              e.preventDefault();
                              onRowClick(row.original);
                            }
                          }
                        : undefined
                    }
                    className={cn(
                      'border-b border-border/30 last:border-0 transition-colors',
                      'hover:bg-muted/30',
                      row.getIsSelected() && 'bg-primary/5',
                      onRowClick &&
                        'cursor-pointer focus-visible:outline-none focus-visible:bg-muted/40 focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring'
                    )}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td
                        key={cell.id}
                        className={cn(
                          'align-middle',
                          density === 'compact' ? 'px-3' : 'px-4',
                          // Compact rows also use the small text size, so a
                          // long inventory fits more columns before it scrolls.
                          density === 'compact' ? 'py-2 text-sm' : 'py-3',
                          cell.column.id === 'actions' && 'text-right',
                          alignClass(cell.column.id),
                          columnMeta.get(cell.column.id)?.className
                        )}
                      >
                        {flexRender(
                          cell.column.columnDef.cell,
                          cell.getContext()
                        )}
                      </td>
                    ))}
                    {extraMenuColumn && <td className="w-10" />}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {paginated && (
            <Pagination 
              table={table} 
              pageSizeOptions={pageSizeOptions} 
              itemName={itemNameProp}
              totalCount={totalCount}
            />
          )}
        </>
      )}
    </>
  );

  // Embedded mode: no Card wrapper · renders directly inside an outer Card
  if (embedded) {
    return (
      <div className={cn(className)}>
        {searchable && (
          <div className="px-6 pb-4">
            <SearchBar
              value={globalFilter}
              onChange={setGlobalFilter}
              placeholder={resolvedSearchPlaceholder}
            />
          </div>
        )}
        {tableContent}
      </div>
    );
  }

  // Default mode: wraps table in its own Card
  return (
    <div className={cn('space-y-4', className)}>
      {/* Search Bar */}
      {searchable && (
        <SearchBar
          value={globalFilter}
          onChange={setGlobalFilter}
          placeholder={resolvedSearchPlaceholder}
        />
      )}

      {/* Table */}
      <Card>
        <CardContent className="p-0">
          {tableContent}
        </CardContent>
      </Card>
    </div>
  );
}

// ============================================================================
// Exports
// ============================================================================

export { TableSkeleton, DefaultEmptyState, TableCheckbox };
