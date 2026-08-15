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
  useReactTable,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  flexRender,
  ColumnDef,
  SortingState,
  ColumnFiltersState,
  RowSelectionState,
  Column,
  Row,
} from '@tanstack/react-table';
import {
  ChevronUp,
  ChevronDown,
  ChevronsUpDown,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Search,
} from 'lucide-react';
import { Card, CardContent } from './card';
import { Button } from './button';
import { EmptyState } from './empty-state';
import { Skeleton } from './skeleton';
import { SearchBar } from './search-bar';
import { cn } from '../../lib/utils';

// ============================================================================
// Types
// ============================================================================

export interface DataTableColumn<T> {
  id: string;
  header: string | ReactNode;
  accessorKey?: keyof T;
  accessorFn?: (row: T) => unknown;
  cell?: (row: T) => ReactNode;
  sortable?: boolean;
  className?: string;
  headerClassName?: string;
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
        'h-4 w-4 rounded border-border bg-transparent cursor-pointer',
        'accent-primary focus:ring-primary/20 focus:ring-2 focus:ring-offset-0',
        disabled && 'opacity-50 cursor-not-allowed'
      )}
    />
  );
}

// ============================================================================
// Sort Button Component
// ============================================================================

interface SortButtonProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  column: Column<any, unknown>;
  children: ReactNode;
}

function SortButton({ column, children }: SortButtonProps) {
  const sorted = column.getIsSorted();
  
  return (
    <Button
      variant="ghost"
      size="sm"
      className="-ml-3 h-8 font-medium text-muted-foreground hover:text-foreground"
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

function TableSkeleton({ rows = 10, columns = 6 }: { rows?: number; columns?: number }) {
  return (
    <Card>
      <CardContent className="p-0">
        <div className="space-y-0">
          {/* Header skeleton */}
          <div className="flex items-center gap-4 h-12 px-4 border-b border-border/50 bg-muted/30">
            <Skeleton className="h-[18px] w-[18px] rounded" />
            {Array.from({ length: columns - 1 }).map((_, i) => (
              <Skeleton key={i} className="h-4 flex-1 max-w-[100px]" />
            ))}
          </div>
          {/* Row skeletons */}
          {Array.from({ length: rows }).map((_, i) => (
            <div key={i} className="flex items-center gap-4 px-4 py-3 border-b border-border/30 last:border-0">
              <Skeleton className="h-[18px] w-[18px] rounded" />
              <Skeleton className="h-10 w-10 rounded-lg" />
              <div className="flex-1 space-y-1.5">
                <Skeleton className="h-4 w-[180px]" />
                <Skeleton className="h-3 w-[120px]" />
              </div>
              <Skeleton className="h-6 w-14 rounded-full" />
              <Skeleton className="h-4 w-20" />
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-6 w-16 rounded-full" />
              <Skeleton className="h-8 w-16" />
            </div>
          ))}
        </div>
      </CardContent>
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

interface PaginationProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  table: ReturnType<typeof useReactTable<any>>;
  pageSizeOptions: number[];
  itemName: string;
  totalCount?: number;
}

function Pagination({ table, pageSizeOptions, itemName, totalCount }: PaginationProps) {
  const { t } = useTranslation('common');
  const { pageIndex, pageSize } = table.getState().pagination;
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
            className="h-8 rounded border border-input bg-background px-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
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
  onRowClick,
  className,
  paginated = true,
  pageSizeOptions = [10, 25, 50, 100],
  defaultPageSize = 25,
  itemName: itemNameProp = 'items',
  totalCount,
  embedded = false,
}: DataTableProps<T>) {
  const { t } = useTranslation('common');
  const resolvedSearchPlaceholder = searchPlaceholder ?? t('DataTable.searchPlaceholder');
  const [sorting, setSorting] = useState<SortingState>([]);
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [globalFilter, setGlobalFilter] = useState('');

  // Convert our column definitions to TanStack Table format
  const columns = useMemo<ColumnDef<T>[]>(() => {
    const cols: ColumnDef<T>[] = [];

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
        cell: ({ row }) => (
          <TableCheckbox
            checked={row.getIsSelected()}
            onChange={(checked) => row.toggleSelected(checked)}
            aria-label={t('DataTable.selectRow')}
          />
        ),
        enableSorting: false,
        enableHiding: false,
      });
    }

    // Add data columns · only include accessorKey/accessorFn/cell when defined
    // to avoid overriding TanStack Table defaults with undefined
    columnDefs.forEach((col) => {
      const colDef: ColumnDef<T> = {
        id: col.id,
        header: col.sortable !== false
          ? ({ column }: { column: Column<T, unknown> }) => <SortButton column={column}>{col.header}</SortButton>
          : () => <span className="font-medium text-muted-foreground text-sm">{col.header}</span>,
        enableSorting: col.sortable !== false,
      };
      if (col.accessorKey != null) (colDef as ColumnDef<T> & { accessorKey: string }).accessorKey = col.accessorKey as string;
      if (col.accessorFn) (colDef as ColumnDef<T> & { accessorFn: (row: T) => unknown }).accessorFn = col.accessorFn;
      if (col.cell) colDef.cell = ({ row }: { row: Row<T> }) => col.cell!(row.original);
      cols.push(colDef);
    });

    return cols;
  }, [columnDefs, selectable, t]);

  const table = useReactTable({
    data,
    columns,
    state: {
      sorting,
      columnFilters,
      rowSelection,
      globalFilter,
    },
    enableRowSelection: selectable,
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    onRowSelectionChange: setRowSelection,
    onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: paginated ? getPaginationRowModel() : undefined,
    getSortedRowModel: getSortedRowModel(),
    getRowId: (row) => getRowId(row),
    initialState: {
      pagination: {
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

  // Show loading skeleton
  if (isLoading) {
    return <TableSkeleton rows={skeletonRows} columns={columns.length} />;
  }

  // Shared table + pagination markup
  const tableContent = (
    <>
      {data.length === 0 && !globalFilter ? (
        emptyState || <DefaultEmptyState searchQuery={globalFilter} itemName={itemNameProp} />
      ) : table.getRowModel().rows.length === 0 ? (
        <DefaultEmptyState searchQuery={globalFilter} itemName={itemNameProp} />
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full" aria-label={t('DataTable.tableAriaLabel', { itemName: itemNameProp })}>
              <thead>
                <tr className="border-b border-border/50">
                  {table.getHeaderGroups().map((headerGroup) =>
                    headerGroup.headers.map((header) => (
                      <th
                        key={header.id}
                        className={cn(
                          'h-12 px-4 text-left align-middle text-sm font-medium text-muted-foreground',
                          header.id === 'select' && 'w-12',
                          header.id === 'actions' && 'text-right'
                        )}
                      >
                        {header.isPlaceholder
                          ? null
                          : flexRender(
                              header.column.columnDef.header,
                              header.getContext()
                            )}
                      </th>
                    ))
                  )}
                </tr>
              </thead>
              <tbody>
                {table.getRowModel().rows.map((row) => (
                  <tr
                    key={row.id}
                    onClick={() => onRowClick?.(row.original)}
                    className={cn(
                      'border-b border-border/30 last:border-0 transition-colors',
                      'hover:bg-muted/30',
                      row.getIsSelected() && 'bg-primary/5',
                      onRowClick && 'cursor-pointer'
                    )}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td
                        key={cell.id}
                        className={cn(
                          'px-4 py-3',
                          cell.column.id === 'actions' && 'text-right'
                        )}
                      >
                        {flexRender(
                          cell.column.columnDef.cell,
                          cell.getContext()
                        )}
                      </td>
                    ))}
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
          placeholder={searchPlaceholder}
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
