// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * FreeSDN · Drivers Page
 *
 * Canonical list-page pattern. Drivers are read-only (sourced from backend
 * registry), but the page still supports search, filter, bulk-select, and
 * detail dialog.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useQuery } from '@tanstack/react-query';
import {
  Cpu,
  ExternalLink,
  Info,
  CheckCircle,
  Server,
  Wifi,
  Shield,
  Network,
  Eye,
  Download,
  MoreHorizontal,
} from 'lucide-react';
import { PageHeader, PageToolbar } from '@/components/layout';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { SearchBar } from '@/components/ui/search-bar';
import { DataTable, type DataTableColumn } from '@/components/ui/data-table';
import { StatsGrid } from '@/components/ui/stats-grid';
import { BulkActionsBar } from '@/components/ui/bulk-actions-bar';
import { ErrorState } from '@/components/ui/empty-state';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { discoveryApi, type Driver } from '@/lib/api';
import { safeExternalUrl } from '@/lib/utils';

type DeviceTypeFilter = 'all' | 'switch' | 'router' | 'camera' | 'access_point' | 'nvr';

function getDeviceIcon(deviceTypes: string[]) {
  const types = deviceTypes.map((t) => t.toLowerCase()).join(' ');
  if (types.includes('switch')) return Network;
  if (types.includes('router') || types.includes('gateway')) return Wifi;
  if (types.includes('camera') || types.includes('nvr')) return Shield;
  return Server;
}

export default function DriversPage() {
  const { t } = useTranslation('drivers');
  const [searchQuery, setSearchQuery] = useState('');
  const [deviceTypeFilter, setDeviceTypeFilter] = useState<DeviceTypeFilter>('all');
  const [vendorFilter, setVendorFilter] = useState<string>('all');
  const [selectedDriver, setSelectedDriver] = useState<Driver | null>(null);
  const [detailsDialogOpen, setDetailsDialogOpen] = useState(false);
  const [selectedRows, setSelectedRows] = useState<Driver[]>([]);

  // Fetch drivers
  const {
    data: driversData,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['drivers'],
    queryFn: async () => {
      const response = await discoveryApi.listDrivers();
      return response.data;
    },
  });

  // Fetch driver details when dialog is open
  const { data: driverDetails, isLoading: detailsLoading } = useQuery({
    queryKey: ['driver-details', selectedDriver?.id],
    queryFn: async () => {
      if (!selectedDriver?.id) return null;
      const response = await discoveryApi.getDriverDetails(selectedDriver.id);
      return response.data;
    },
    enabled: !!selectedDriver && detailsDialogOpen,
  });

  const allDrivers: Driver[] = driversData ?? [];

  // Filter
  const filteredDrivers = allDrivers.filter((driver) => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matches =
        driver.name.toLowerCase().includes(q) ||
        driver.vendor.toLowerCase().includes(q) ||
        driver.device_types.some((dt) => dt.toLowerCase().includes(q));
      if (!matches) return false;
    }
    if (
      deviceTypeFilter !== 'all' &&
      !driver.device_types.some((dt) => dt.toLowerCase().includes(deviceTypeFilter))
    ) {
      return false;
    }
    if (vendorFilter !== 'all' && driver.vendor !== vendorFilter) return false;
    return true;
  });

  // Stats
  const stats = {
    totalDrivers: allDrivers.length,
    vendors: new Set(allDrivers.map((d) => d.vendor)).size,
    deviceTypes: new Set(allDrivers.flatMap((d) => d.device_types)).size,
    capabilities: new Set(allDrivers.flatMap((d) => d.capabilities || [])).size,
  };

  const vendors = Array.from(new Set(allDrivers.map((d) => d.vendor))).sort();

  const hasActiveFilters =
    searchQuery !== '' || deviceTypeFilter !== 'all' || vendorFilter !== 'all';
  const handleClearFilters = () => {
    setSearchQuery('');
    setDeviceTypeFilter('all');
    setVendorFilter('all');
  };

  const handleViewDetails = (driver: Driver) => {
    setSelectedDriver(driver);
    setDetailsDialogOpen(true);
  };

  // Client-side CSV export from already-loaded rows.
  const exportToCsv = (rows: Driver[]) => {
    if (rows.length === 0) return;
    const headers = ['id', 'name', 'vendor', 'version', 'device_types', 'capabilities'];
    const escape = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    const csv = [
      headers.join(','),
      ...rows.map((d) =>
        [
          d.id,
          d.name,
          d.vendor,
          d.version,
          (d.device_types ?? []).join('; '),
          (d.capabilities ?? []).join('; '),
        ]
          .map(escape)
          .join(','),
      ),
    ].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `drivers-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Columns
  const columns: DataTableColumn<Driver>[] = [
    {
      id: 'name',
      header: t('DriversPage.columns.driver'),
      accessorKey: 'name',
      cell: (driver) => {
        const Icon = getDeviceIcon(driver.device_types);
        return (
          <button
            className="flex items-center gap-3 text-left min-w-0"
            onClick={() => handleViewDetails(driver)}
          >
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-muted flex-shrink-0">
              <Icon className="h-4 w-4 text-muted-foreground" />
            </div>
            <div className="min-w-0">
              <div className="font-medium hover:text-primary hover:underline truncate">
                {driver.name}
              </div>
              <div className="text-xs text-muted-foreground truncate">{driver.vendor}</div>
            </div>
          </button>
        );
      },
    },
    {
      id: 'version',
      header: t('DriversPage.columns.version'),
      accessorKey: 'version',
      cell: (driver) => (
        <Badge variant="secondary" className="font-mono text-xs">
          v{driver.version}
        </Badge>
      ),
    },
    {
      id: 'device_types',
      header: t('DriversPage.columns.deviceTypes'),
      accessorFn: (d) => d.device_types.join(', '),
      cell: (driver) => (
        <div className="flex flex-wrap items-center gap-1 max-w-[280px]">
          {driver.device_types.slice(0, 3).map((type) => (
            <Badge key={type} variant="outline" className="text-xs">
              {type}
            </Badge>
          ))}
          {driver.device_types.length > 3 && (
            <Badge variant="outline" className="text-xs">
              +{driver.device_types.length - 3}
            </Badge>
          )}
        </div>
      ),
    },
    {
      id: 'capabilities',
      header: t('DriversPage.columns.capabilities'),
      accessorFn: (d) => (d.capabilities ?? []).length,
      cell: (driver) => {
        const caps = driver.capabilities ?? [];
        if (caps.length === 0) {
          return <span className="text-xs text-muted-foreground">-</span>;
        }
        return (
          <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
            <Info className="h-3 w-3" />
            {caps.slice(0, 2).join(', ')}
            {caps.length > 2 && <span>+{caps.length - 2}</span>}
          </span>
        );
      },
    },
    {
      id: 'actions',
      header: '',
      sortable: false,
      cell: (driver) => (
        <div className="flex justify-end" onClick={(e) => e.stopPropagation()}>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="h-8 w-8" aria-label={t('DriversPage.actions.actionsFor', { name: driver.name })}>
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => handleViewDetails(driver)}>
                <Eye className="h-4 w-4 mr-2" />
                {t('DriversPage.actions.viewDetails')}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      ),
    },
  ];

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader
          title={t('DriversPage.title')}
          description={t('DriversPage.description')}
          icon={Cpu}
        />
        <ErrorState
          message={error instanceof Error ? error.message : t('DriversPage.errors.loadFailed')}
          onRetry={() => refetch()}
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <PageHeader
        title={t('DriversPage.title')}
        description={t('DriversPage.description')}
        icon={Cpu}
        onRefresh={() => refetch()}
        refreshing={isLoading}
        secondaryActions={[
          {
            label: t('DriversPage.actions.export'),
            icon: Download,
            onClick: () => exportToCsv(filteredDrivers),
          },
        ]}
      />

      {/* Stats */}
      <StatsGrid
        columns={4}
        isLoading={isLoading}
        stats={[
          {
            title: t('DriversPage.stats.totalDrivers.title'),
            value: stats.totalDrivers,
            icon: Cpu,
            variant: 'default',
            description: t('DriversPage.stats.totalDrivers.description'),
          },
          {
            title: t('DriversPage.stats.vendors.title'),
            value: stats.vendors,
            icon: Server,
            variant: 'success',
            description: t('DriversPage.stats.vendors.description'),
          },
          {
            title: t('DriversPage.stats.deviceTypes.title'),
            value: stats.deviceTypes,
            icon: Network,
            variant: 'info',
            description: t('DriversPage.stats.deviceTypes.description'),
          },
          {
            title: t('DriversPage.stats.capabilities.title'),
            value: stats.capabilities,
            icon: CheckCircle,
            variant: 'default',
            description: t('DriversPage.stats.capabilities.description'),
          },
        ]}
      />

      {/* Toolbar */}
      <PageToolbar>
        <SearchBar
          value={searchQuery}
          onChange={setSearchQuery}
          placeholder={t('DriversPage.filters.searchPlaceholder')}
          className="w-full sm:w-auto"
        />
        <Select value={vendorFilter} onValueChange={setVendorFilter}>
          <SelectTrigger className="w-full sm:w-[180px]">
            <SelectValue placeholder={t('DriversPage.filters.allVendors')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('DriversPage.filters.allVendors')}</SelectItem>
            {vendors.map((v) => (
              <SelectItem key={v} value={v}>
                {v}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select
          value={deviceTypeFilter}
          onValueChange={(v) => setDeviceTypeFilter(v as DeviceTypeFilter)}
        >
          <SelectTrigger className="w-full sm:w-[180px]">
            <SelectValue placeholder={t('DriversPage.filters.allDeviceTypes')} />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{t('DriversPage.filters.allDeviceTypes')}</SelectItem>
            <SelectItem value="switch">{t('DriversPage.deviceTypes.switches')}</SelectItem>
            <SelectItem value="router">{t('DriversPage.deviceTypes.routers')}</SelectItem>
            <SelectItem value="access_point">{t('DriversPage.deviceTypes.accessPoints')}</SelectItem>
            <SelectItem value="camera">{t('DriversPage.deviceTypes.cameras')}</SelectItem>
            <SelectItem value="nvr">{t('DriversPage.deviceTypes.nvrs')}</SelectItem>
          </SelectContent>
        </Select>
        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={handleClearFilters}>
            {t('DriversPage.filters.clearFilters')}
          </Button>
        )}
      </PageToolbar>

      {/* Table */}
      <DataTable
        data={filteredDrivers}
        columns={columns}
        isLoading={isLoading}
        selectable
        onSelectionChange={setSelectedRows}
        searchable={false}
        itemName={t('DriversPage.itemNamePlural')}
        getRowId={(d) => d.id}
        onRowClick={(d) => handleViewDetails(d)}
      />

      {/* Bulk actions */}
      <BulkActionsBar
        selectedCount={selectedRows.length}
        itemName={t('DriversPage.itemName')}
        onClear={() => setSelectedRows([])}
        actions={[
          {
            label: t('DriversPage.actions.export'),
            icon: Download,
            onClick: () => exportToCsv(selectedRows),
          },
        ]}
      />

      {/* Driver Details Dialog */}
      <Dialog open={detailsDialogOpen} onOpenChange={setDetailsDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Cpu className="h-5 w-5" />
              {selectedDriver?.name}
            </DialogTitle>
            <DialogDescription>
              {selectedDriver?.vendor} • {t('DriversPage.dialog.versionLabel', { version: selectedDriver?.version })}
            </DialogDescription>
          </DialogHeader>

          {detailsLoading ? (
            <div className="space-y-4">
              <Skeleton className="h-20 w-full" />
              <Skeleton className="h-32 w-full" />
            </div>
          ) : driverDetails ? (
            <Tabs defaultValue="overview" className="w-full">
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="overview">{t('DriversPage.tabs.overview')}</TabsTrigger>
                <TabsTrigger value="capabilities">{t('DriversPage.tabs.capabilities')}</TabsTrigger>
                <TabsTrigger value="config">{t('DriversPage.tabs.configuration')}</TabsTrigger>
              </TabsList>

              <TabsContent value="overview" className="space-y-4">
                <div className="rounded-lg border bg-muted/50 p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">{t('DriversPage.overview.driverId')}</span>
                    <code className="text-sm bg-muted px-2 py-1 rounded">
                      {driverDetails.id}
                    </code>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">{t('DriversPage.overview.version')}</span>
                    <Badge variant="secondary">{driverDetails.version}</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">{t('DriversPage.overview.vendor')}</span>
                    <span className="font-medium">{driverDetails.vendor}</span>
                  </div>
                </div>

                <div>
                  <h4 className="text-sm font-medium mb-2">{t('DriversPage.overview.supportedDeviceTypes')}</h4>
                  <div className="flex flex-wrap gap-2">
                    {driverDetails.device_types.map((type) => (
                      <Badge key={type} variant="outline">
                        {type}
                      </Badge>
                    ))}
                  </div>
                </div>

                {driverDetails.description && (
                  <div>
                    <h4 className="text-sm font-medium mb-2">{t('DriversPage.overview.descriptionHeading')}</h4>
                    <p className="text-sm text-muted-foreground">{driverDetails.description}</p>
                  </div>
                )}

                {safeExternalUrl(driverDetails.documentation_url) && (
                  <Button variant="outline" asChild>
                    <a
                      href={safeExternalUrl(driverDetails.documentation_url)!}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      <ExternalLink className="h-4 w-4 mr-2" />
                      {t('DriversPage.overview.viewDocumentation')}
                    </a>
                  </Button>
                )}
              </TabsContent>

              <TabsContent value="capabilities" className="space-y-4">
                <div className="grid grid-cols-2 gap-2">
                  {driverDetails.capabilities?.map((capability) => (
                    <div
                      key={capability}
                      className="flex items-center gap-2 p-2 rounded-lg bg-muted/50"
                    >
                      <CheckCircle className="h-4 w-4 text-success" />
                      <span className="text-sm">{capability}</span>
                    </div>
                  ))}
                </div>
                {(!driverDetails.capabilities || driverDetails.capabilities.length === 0) && (
                  <p className="text-sm text-muted-foreground">
                    {t('DriversPage.capabilities.empty')}
                  </p>
                )}
              </TabsContent>

              <TabsContent value="config" className="space-y-4">
                {driverDetails.config_schema ? (
                  <div className="rounded-lg border p-4">
                    <pre className="text-xs overflow-auto">
                      {JSON.stringify(driverDetails.config_schema, null, 2)}
                    </pre>
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    {t('DriversPage.config.empty')}
                  </p>
                )}
              </TabsContent>
            </Tabs>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}
