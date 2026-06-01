// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useSiteStore } from '@/stores/siteStore';
import { motion } from 'framer-motion';
import {
  Zap,
  Power,
  AlertTriangle,
  Settings,
  MoreVertical,
  Clock,
  ToggleLeft,
  ToggleRight,
  Activity,
  Calendar,
  Plus,
  Trash2,
  Edit,
  RefreshCw,
  Ban,
  Info,
} from 'lucide-react';
import { PageHeader, PageTabs, type PageTab } from '@/components/layout';
import { StatsGrid } from '@/components/ui/stats-grid';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { SearchBar } from '@/components/ui/search-bar';
import { Badge } from '@/components/ui/badge';
import { EmptyState } from '@/components/ui/empty-state';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { Progress } from '@/components/ui/progress';
import { Slider } from '@/components/ui/slider';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { poeApi, getApiErrorMessage } from '@/lib/api';
import { useToastHelpers } from '@/components/ui/toast';
import { useDeviceCapabilities } from '@/hooks/useDeviceCapabilities';

// Types
interface PoEPort {
  port_id: string;
  port_index: number;
  port_name: string;
  device_id: string;
  device_name: string;
  poe_enabled: boolean;
  poe_mode: string;
  poe_status: string;
  power_draw: number;
  power_limit: number;
  power_class?: number;
  voltage?: number;
  current?: number;
  pd_type?: string;
}

// Backend PoEScheduleDetailOut shape (poe.py). The shared lib `PoESchedule`
// type lags this contract (is_enabled/start_time/end_time/action/...), so we
// read the real backend fields here to avoid the blank-card / always-off drift.
interface PoEScheduleDetail {
  id: string;
  name: string;
  enabled: boolean;
  device_id?: string | null;
  device_group_id?: string | null;
  port_numbers: number[];
  power_off_time: string;
  power_on_time: string;
  days_of_week: number[];
  timezone: string;
  last_action?: string | null;
  last_action_at?: string | null;
}



// Helper functions
type TFunc = (key: string, options?: Record<string, unknown>) => string;

const getPdTypeLabel = (t: TFunc, type?: string) => {
  const labels: Record<string, string> = {
    access_point: t('PoEPage.pdTypes.access_point'),
    camera: t('PoEPage.pdTypes.camera'),
    ip_phone: t('PoEPage.pdTypes.ip_phone'),
    iot: t('PoEPage.pdTypes.iot'),
  };
  return type ? labels[type] || type : t('PoEPage.pdTypes.unknown');
};

const getStatusColor = (status: string) => {
  switch (status) {
    case 'delivering':
      return 'bg-success';
    case 'searching':
      return 'bg-warning';
    case 'fault':
      return 'bg-destructive';
    default:
      return 'bg-muted-foreground';
  }
};

const getModeLabel = (t: TFunc, mode: string) => {
  const labels: Record<string, string> = {
    auto: t('PoEPage.modes.auto'),
    poe: '802.3af (15.4W)',
    'poe+': '802.3at (30W)',
    'poe++': '802.3bt (60W)',
    passive24: t('PoEPage.modes.passive24'),
    passive48: t('PoEPage.modes.passive48'),
    disabled: t('PoEPage.modes.disabled'),
  };
  return labels[mode] || mode;
};

export default function PoEPage() {
  const { t } = useTranslation('poe');
  const toast = useToastHelpers();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const [selectedDevice, setSelectedDevice] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [portDialogOpen, setPortDialogOpen] = useState(false);
  const [scheduleDialogOpen, setScheduleDialogOpen] = useState(false);
  const [selectedPort, setSelectedPort] = useState<PoEPort | null>(null);
  const [bulkSelectMode, setBulkSelectMode] = useState(false);
  const [selectedPorts, setSelectedPorts] = useState<string[]>([]);

  // Site context
  const selectedSiteId = useSiteStore((s) => s.selectedSiteId);

  // Fetch PoE switches from API
  const {
    data: switches,
    isLoading: switchesLoading,
    isError: isErrorSwitches,
    refetch: refetchSwitches
  } = useQuery({
    queryKey: ['poe-switches', { siteId: selectedSiteId }],
    queryFn: async () => {
      const response = await poeApi.listSwitches(selectedSiteId || undefined);
      return response.data;
    },
    staleTime: 30000, // 30 seconds
  });

  // Fetch PoE ports from API
  const { 
    data: ports,
    isLoading: portsLoading,
    isError: isErrorPorts,
    refetch: refetchPorts
  } = useQuery({
    queryKey: ['poe-ports', selectedDevice, { siteId: selectedSiteId }],
    queryFn: async () => {
      const response = await poeApi.listPorts({
        device_id: selectedDevice || undefined,
        site_id: selectedSiteId || undefined,
      });
      return response.data;
    },
    staleTime: 30000,
  });

  // Fetch schedules from API
  const { 
    data: schedules,
    isLoading: schedulesLoading,
    isError: isErrorSchedules,
    refetch: refetchSchedules
  } = useQuery({
    queryKey: ['poe-schedules', { siteId: selectedSiteId }],
    queryFn: async () => {
      const response = await poeApi.listSchedules(selectedSiteId || undefined);
      return response.data;
    },
    staleTime: 60000,
  });

  const hasQueryError = isErrorSwitches || isErrorPorts || isErrorSchedules;
  const isRefreshing = switchesLoading || portsLoading;

  const handleRefresh = async () => {
    await Promise.all([
      refetchSwitches(),
      refetchPorts(),
      refetchSchedules(),
    ]);
  };

  // Port edit form state
  const [portForm, setPortForm] = useState({
    poe_enabled: true,
    poe_mode: 'auto',
    power_limit: 30,
    priority: 3,
  });

  // Schedule form state.
  // start_time/end_time map to the backend power_off_time/power_on_time fields.
  const [editingScheduleId, setEditingScheduleId] = useState<string | null>(null);
  const [scheduleSaving, setScheduleSaving] = useState(false);
  const [scheduleForm, setScheduleForm] = useState({
    name: '',
    device_id: '',
    port_numbers: [] as number[],
    days_of_week: [0, 1, 2, 3, 4],
    start_time: '22:00',
    end_time: '06:00',
    action: 'disable',
    enabled: true,
  });

  // Ports for the device selected inside the Schedule dialog. Drives the
  // port multi-select so a created schedule always carries a real target the
  // Celery evaluator can act on (it skips schedules with no device + ports).
  const {
    data: scheduleDevicePorts,
    isLoading: scheduleDevicePortsLoading,
  } = useQuery({
    queryKey: ['poe-schedule-device-ports', scheduleForm.device_id],
    queryFn: async () => {
      const response = await poeApi.getDevicePorts(scheduleForm.device_id);
      return response.data;
    },
    enabled: scheduleDialogOpen && !!scheduleForm.device_id,
    staleTime: 30000,
  });

  // Use API data or fallback to empty arrays.
  // Cast schedules to the real backend shape (see PoEScheduleDetail note above).
  const devices = switches || [];
  const poeSchedulesList = (schedules as unknown as PoEScheduleDetail[]) || [];

  const totalPower = devices.reduce((sum, d) => sum + d.power_used, 0);
  const totalBudget = devices.reduce((sum, d) => sum + d.power_budget, 0);
  const totalActivePorts = devices.reduce((sum, d) => sum + d.active_poe_ports, 0);
  const devicesNearBudget = devices.filter(d => d.near_budget).length;

  // Filter ports based on selection and search
  const filteredPorts = useMemo(() => {
    const poePortsList = ports ?? [];
    return poePortsList.filter(port => {
      if (selectedDevice && port.device_id !== selectedDevice) return false;
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        return (
          port.port_name.toLowerCase().includes(query) ||
          port.device_name.toLowerCase().includes(query) ||
          (port.pd_type && port.pd_type.toLowerCase().includes(query))
        );
      }
      return true;
    });
  }, [ports, selectedDevice, searchQuery]);

  // Capability check for selected device
  const {
    canPoeControl,
    getDisabledReason,
    isLoading: capsLoading,
  } = useDeviceCapabilities(selectedDevice);
  
  // Determine if PoE controls should be shown for this device
  const showPoeControls = !selectedDevice || canPoeControl;
  const poeDisabledReason = selectedDevice ? getDisabledReason('port.poe_control') : undefined;

  const handlePortEdit = (port: PoEPort) => {
    setSelectedPort(port);
    setPortForm({
      poe_enabled: port.poe_enabled,
      poe_mode: port.poe_mode,
      power_limit: port.power_limit,
      priority: 3,
    });
    setPortDialogOpen(true);
  };

  const handlePortSave = async () => {
    if (!selectedPort) return;

    try {
      // poeApi.updatePort (PATCH /poe/ports/{id}) is the wired backend route.
      // The previous devicePortsApi.setPoeState path posted to
      // /devices/{id}/ports/{n}/poe, which has no backend route -> silent 404.
      await poeApi.updatePort(selectedPort.port_id, {
        poe_enabled: portForm.poe_enabled,
        poe_mode: portForm.poe_mode,
        power_limit: portForm.power_limit,
        priority: portForm.priority,
      });
      queryClient.invalidateQueries({ queryKey: ['poe-ports'] });
      setPortDialogOpen(false);
      toast.success(t('PoEPage.toast.updated'));
    } catch (error) {
      toast.error(t('PoEPage.toast.updateFailed'), getApiErrorMessage(error));
    }
  };

  const handlePortReset = async (portId: string) => {
    try {
      // poeApi.cyclePort (POST /poe/ports/{id}/reset) is the wired route; the
      // old devicePortsApi.cyclePoePort path had no backend route (404).
      await poeApi.cyclePort(portId);
      queryClient.invalidateQueries({ queryKey: ['poe-ports'] });
      toast.success(t('PoEPage.toast.reset'));
    } catch (error) {
      toast.error(t('PoEPage.toast.resetFailed'), getApiErrorMessage(error));
    }
  };

  const handleBulkToggle = async (enabled: boolean) => {
    if (selectedPorts.length === 0) return;
    try {
      await poeApi.bulkUpdate({
        port_ids: selectedPorts,
        poe_enabled: enabled,
      });
      queryClient.invalidateQueries({ queryKey: ['poe-ports'] });
      // Only clear the selection on success so a failed bulk toggle keeps the
      // ports selected and the operator can retry.
      setSelectedPorts([]);
      setBulkSelectMode(false);
    } catch (error) {
      toast.error(t('PoEPage.toast.bulkUpdateFailed'), getApiErrorMessage(error));
    }
  };

  // --- Schedule handlers ---------------------------------------------------

  const resetScheduleForm = () => {
    setEditingScheduleId(null);
    setScheduleForm({
      name: '',
      device_id: '',
      port_numbers: [],
      days_of_week: [0, 1, 2, 3, 4],
      start_time: '22:00',
      end_time: '06:00',
      action: 'disable',
      enabled: true,
    });
  };

  const handleScheduleOpenCreate = () => {
    resetScheduleForm();
    setScheduleDialogOpen(true);
  };

  const handleScheduleOpenEdit = (schedule: PoEScheduleDetail) => {
    setEditingScheduleId(schedule.id);
    setScheduleForm({
      name: schedule.name,
      device_id: schedule.device_id ?? '',
      port_numbers: schedule.port_numbers ?? [],
      days_of_week: schedule.days_of_week ?? [],
      start_time: schedule.power_off_time || '22:00',
      end_time: schedule.power_on_time || '06:00',
      action: 'disable',
      enabled: schedule.enabled,
    });
    setScheduleDialogOpen(true);
  };

  const handleScheduleSave = async () => {
    setScheduleSaving(true);
    try {
      // Map FE form -> backend PoEScheduleCreateIn/UpdateIn contract.
      // device_id + port_numbers are the target the Celery evaluator acts on;
      // without them a schedule is permanently inert (evaluator skips it).
      const payload = {
        name: scheduleForm.name,
        enabled: scheduleForm.enabled,
        device_id: scheduleForm.device_id,
        port_numbers: scheduleForm.port_numbers,
        power_off_time: scheduleForm.start_time,
        power_on_time: scheduleForm.end_time,
        days_of_week: scheduleForm.days_of_week,
      };
      if (editingScheduleId) {
        await poeApi.updateSchedule(editingScheduleId, payload as never);
      } else {
        await poeApi.createSchedule(selectedSiteId || '', payload as never);
      }
      queryClient.invalidateQueries({ queryKey: ['poe-schedules'] });
      setScheduleDialogOpen(false);
      resetScheduleForm();
      toast.success(t('PoEPage.toast.updated'));
    } catch (error) {
      toast.error(t('PoEPage.toast.updateFailed'), getApiErrorMessage(error));
    } finally {
      setScheduleSaving(false);
    }
  };

  const handleScheduleToggle = async (schedule: PoEScheduleDetail, enabled: boolean) => {
    try {
      await poeApi.updateSchedule(schedule.id, { enabled } as never);
      queryClient.invalidateQueries({ queryKey: ['poe-schedules'] });
    } catch (error) {
      toast.error(t('PoEPage.toast.updateFailed'), getApiErrorMessage(error));
    }
  };

  const handleScheduleDelete = async (schedule: PoEScheduleDetail) => {
    if (!window.confirm(t('PoEPage.schedules.menu.delete') + ': ' + schedule.name)) return;
    try {
      await poeApi.deleteSchedule(schedule.id);
      queryClient.invalidateQueries({ queryKey: ['poe-schedules'] });
      toast.success(t('PoEPage.toast.updated'));
    } catch (error) {
      toast.error(t('PoEPage.toast.updateFailed'), getApiErrorMessage(error));
    }
  };

  const handlePortPoeToggle = async (port: PoEPort) => {
    try {
      await poeApi.updatePort(port.port_id, { poe_enabled: !port.poe_enabled });
      queryClient.invalidateQueries({ queryKey: ['poe-ports'] });
      toast.success(t('PoEPage.toast.updated'));
    } catch (error) {
      toast.error(t('PoEPage.toast.updateFailed'), getApiErrorMessage(error));
    }
  };

  return (
    <div className="space-y-6">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <PageHeader
            title={t('PoEPage.header.title')}
            description={t('PoEPage.header.description')}
            icon={Zap}
            onRefresh={handleRefresh}
            refreshing={isRefreshing}
          />
        </motion.div>

        {hasQueryError && (
          <Card className="border-destructive">
            <CardContent noOffset className="p-4 flex items-center gap-3">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              <span className="text-sm">{t('PoEPage.errors.partialLoad')}</span>
            </CardContent>
          </Card>
        )}

        {/* Capability Warning Banner */}
        {selectedDevice && !canPoeControl && !capsLoading && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            className="bg-warning/10 border border-warning/20 rounded-lg p-4"
          >
            <div className="flex items-center gap-3">
              <Ban className="h-5 w-5 text-warning" />
              <div>
                <p className="font-medium text-warning">{t('PoEPage.capability.title')}</p>
                <p className="text-sm text-warning/80">
                  {poeDisabledReason || t('PoEPage.capability.defaultReason')}
                </p>
              </div>
            </div>
          </motion.div>
        )}

      <StatsGrid
        columns={4}
        isLoading={switchesLoading}
        stats={[
          {
            title: t('PoEPage.stats.totalPower.title'),
            value: `${totalPower.toFixed(1)}W`,
            icon: Zap,
            variant: totalBudget > 0 && totalPower / totalBudget > 0.9 ? 'destructive' : 'warning',
            description: totalBudget > 0
              ? t('PoEPage.stats.totalPower.description', {
                  budget: totalBudget,
                  percent: ((totalPower / totalBudget) * 100).toFixed(0),
                })
              : '-',
          },
          {
            title: t('PoEPage.stats.activePorts.title'),
            value: totalActivePorts,
            icon: Power,
            variant: 'success',
            description: t('PoEPage.stats.activePorts.description'),
          },
          {
            title: t('PoEPage.stats.switches.title'),
            value: devices.length,
            icon: Activity,
            variant: 'info',
            description: t('PoEPage.stats.switches.description', {
              count: devices.filter((d) => d.fault_poe_ports > 0).length,
            }),
          },
          {
            title: t('PoEPage.stats.budgetWarnings.title'),
            value: devicesNearBudget,
            icon: AlertTriangle,
            variant: devicesNearBudget > 0 ? 'warning' : 'default',
            description: t('PoEPage.stats.budgetWarnings.description'),
          },
        ]}
      />

      {/* Main Content */}
      <PageTabs
        basePath="/poe"
        tabs={[
          {
            value: 'devices',
            label: t('PoEPage.tabs.devices'),
            content: (
              <div className="space-y-4">
          {switchesLoading ? (
            <div className="flex items-center justify-center p-8">
              <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : devices.length === 0 ? (
            <EmptyState
              icon={Power}
              title={t('PoEPage.devices.empty.title')}
              description={t('PoEPage.devices.empty.description')}
              variant="card"
            />
          ) : (
          <div className="grid gap-4 md:grid-cols-2">
            {devices.map((device) => (
              <Card
                key={device.device_id}
                className={`cursor-pointer transition-colors hover:bg-muted/50 ${
                  device.near_budget ? 'border-warning' : ''
                } ${device.over_budget ? 'border-destructive' : ''}`}
                onClick={() => {
                  setSelectedDevice(device.device_id);
                  navigate('/poe/ports', { replace: true });
                }}
              >
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-lg">{device.device_name}</CardTitle>
                    <Badge variant="outline">{device.model}</Badge>
                  </div>
                  <CardDescription>
                    {t('PoEPage.devices.card.portsSummary', {
                      total: device.total_poe_ports,
                      active: device.active_poe_ports,
                    })}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {/* Power Usage */}
                    <div>
                      <div className="flex items-center justify-between text-sm mb-1">
                        <span>{t('PoEPage.devices.card.powerUsage')}</span>
                        <span className="font-medium">
                          {device.power_used.toFixed(1)}W / {device.power_budget}W
                        </span>
                      </div>
                      <Progress
                        value={device.power_percentage}
                        className={`h-3 ${
                          device.power_percentage > 90 ? '[&>div]:bg-destructive' :
                          device.power_percentage > 80 ? '[&>div]:bg-warning' :
                          '[&>div]:bg-success'
                        }`}
                      />
                    </div>

                    {/* Port Stats */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-center">
                      <div className="bg-muted rounded-md p-2">
                        <div className="text-lg font-bold text-success">{device.active_poe_ports}</div>
                        <div className="text-xs text-muted-foreground">{t('PoEPage.devices.card.active')}</div>
                      </div>
                      <div className="bg-muted rounded-md p-2">
                        <div className="text-lg font-bold text-muted-foreground">{device.disabled_poe_ports}</div>
                        <div className="text-xs text-muted-foreground">{t('PoEPage.devices.card.disabled')}</div>
                      </div>
                      <div className="bg-muted rounded-md p-2">
                        <div className="text-lg font-bold text-warning">
                          {device.total_poe_ports - device.active_poe_ports - device.disabled_poe_ports - device.fault_poe_ports}
                        </div>
                        <div className="text-xs text-muted-foreground">{t('PoEPage.devices.card.idle')}</div>
                      </div>
                      <div className="bg-muted rounded-md p-2">
                        <div className={`text-lg font-bold ${device.fault_poe_ports > 0 ? 'text-destructive' : 'text-muted-foreground'}`}>
                          {device.fault_poe_ports}
                        </div>
                        <div className="text-xs text-muted-foreground">{t('PoEPage.devices.card.fault')}</div>
                      </div>
                    </div>

                    {/* Warnings */}
                    {device.near_budget && (
                      <div className="flex items-center gap-2 text-sm text-warning bg-warning/10 rounded-md p-2">
                        <AlertTriangle className="h-4 w-4" />
                        {t('PoEPage.devices.card.budgetWarning', {
                          percent: device.power_percentage.toFixed(1),
                        })}
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
          )}
              </div>
            ),
          },
          {
            value: 'ports',
            label: t('PoEPage.tabs.ports'),
            content: (
              <div className="space-y-4">
          {/* Toolbar */}
          <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
            <div className="flex items-center gap-2 w-full sm:w-auto">
              <SearchBar
                value={searchQuery}
                onChange={setSearchQuery}
                placeholder={t('PoEPage.ports.searchPlaceholder')}
              />
              <Select
                value={selectedDevice || 'all'}
                onValueChange={(v) => setSelectedDevice(v === 'all' ? null : v)}
              >
                <SelectTrigger className="w-48">
                  <SelectValue placeholder={t('PoEPage.ports.allDevicesPlaceholder')} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{t('PoEPage.ports.allDevices')}</SelectItem>
                  {devices.map((device) => (
                    <SelectItem key={device.device_id} value={device.device_id}>
                      {device.device_name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="flex items-center gap-2">
              {bulkSelectMode && selectedPorts.length > 0 && showPoeControls && (
                <>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleBulkToggle(true)}
                  >
                    <ToggleRight className="mr-2 h-4 w-4" />
                    {t('PoEPage.ports.bulk.enable', { count: selectedPorts.length })}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleBulkToggle(false)}
                  >
                    <ToggleLeft className="mr-2 h-4 w-4" />
                    {t('PoEPage.ports.bulk.disable', { count: selectedPorts.length })}
                  </Button>
                </>
              )}
              {showPoeControls && (
                <Button
                  variant={bulkSelectMode ? 'secondary' : 'outline'}
                  size="sm"
                  onClick={() => {
                    setBulkSelectMode(!bulkSelectMode);
                    setSelectedPorts([]);
                  }}
                >
                  {bulkSelectMode ? t('PoEPage.ports.bulk.cancel') : t('PoEPage.ports.bulk.select')}
                </Button>
              )}
            </div>
          </div>

          {/* Ports Table */}
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  {bulkSelectMode && <TableHead className="w-12" />}
                  <TableHead>{t('PoEPage.ports.table.port')}</TableHead>
                  <TableHead>{t('PoEPage.ports.table.device')}</TableHead>
                  <TableHead>{t('PoEPage.ports.table.status')}</TableHead>
                  <TableHead>{t('PoEPage.ports.table.mode')}</TableHead>
                  <TableHead>{t('PoEPage.ports.table.power')}</TableHead>
                  <TableHead>{t('PoEPage.ports.table.connectedDevice')}</TableHead>
                  <TableHead className="text-right">{t('PoEPage.ports.table.actions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredPorts.map((port) => (
                  <TableRow key={port.port_id}>
                    {bulkSelectMode && (
                      <TableCell>
                        <input
                          type="checkbox"
                          checked={selectedPorts.includes(port.port_id)}
                          onChange={(e) => {
                            if (e.target.checked) {
                              setSelectedPorts([...selectedPorts, port.port_id]);
                            } else {
                              setSelectedPorts(selectedPorts.filter(id => id !== port.port_id));
                            }
                          }}
                          className="rounded"
                        />
                      </TableCell>
                    )}
                    <TableCell className="font-medium">{port.port_name}</TableCell>
                    <TableCell className="text-muted-foreground">{port.device_name}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <div className={`h-2 w-2 rounded-full ${getStatusColor(port.poe_status)}`} />
                        <span className="capitalize">
                          {t(`PoEPage.ports.statuses.${port.poe_status}`, { defaultValue: port.poe_status })}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{getModeLabel(t, port.poe_mode)}</Badge>
                    </TableCell>
                    <TableCell>
                      {port.poe_status === 'delivering' ? (
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <div className="flex items-center gap-2">
                                <Zap className="h-4 w-4 text-warning" />
                                <span>{port.power_draw.toFixed(1)}W</span>
                                <span className="text-muted-foreground">
                                  / {port.power_limit}W
                                </span>
                              </div>
                            </TooltipTrigger>
                            <TooltipContent>
                              <p>{t('PoEPage.ports.tooltip.class', { value: port.power_class })}</p>
                              <p>{t('PoEPage.ports.tooltip.voltage', { value: port.voltage })}</p>
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      ) : (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {port.pd_type ? (
                        <Badge variant="secondary">
                          {getPdTypeLabel(t, port.pd_type)}
                        </Badge>
                      ) : (
                        <span className="text-muted-foreground">-</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      {showPoeControls ? (
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon">
                              <MoreVertical className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => handlePortEdit(port)}>
                              <Settings className="mr-2 h-4 w-4" />
                              {t('PoEPage.ports.menu.configure')}
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => handlePortReset(port.port_id)}>
                              <RefreshCw className="mr-2 h-4 w-4" />
                              {t('PoEPage.ports.menu.powerCycle')}
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem onClick={() => handlePortPoeToggle(port)}>
                              {port.poe_enabled ? (
                                <>
                                  <ToggleLeft className="mr-2 h-4 w-4" />
                                  {t('PoEPage.ports.menu.disablePoe')}
                                </>
                              ) : (
                                <>
                                  <ToggleRight className="mr-2 h-4 w-4" />
                                  {t('PoEPage.ports.menu.enablePoe')}
                                </>
                              )}
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      ) : (
                        /* PoE controls hidden - show info icon with reason */
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button variant="ghost" size="icon" disabled>
                                <Info className="h-4 w-4 text-muted-foreground" />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>
                              <p>{poeDisabledReason || t('PoEPage.ports.notSupported')}</p>
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Card>
              </div>
            ),
          },
          {
            value: 'schedules',
            label: t('PoEPage.tabs.schedules'),
            content: (
              <div className="space-y-4">
          <div className="flex justify-end">
            <Button onClick={handleScheduleOpenCreate} disabled={!showPoeControls}>
              <Plus className="mr-2 h-4 w-4" />
              {t('PoEPage.schedules.create')}
            </Button>
          </div>

          {schedulesLoading ? (
            <div className="flex items-center justify-center p-8">
              <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : (
          <div className="grid gap-4">
            {poeSchedulesList.map((schedule) => (
              <Card key={schedule.id}>
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Switch
                        checked={schedule.enabled}
                        disabled={!showPoeControls}
                        onCheckedChange={(checked) => handleScheduleToggle(schedule, checked)}
                      />
                      <div>
                        <CardTitle className="text-lg">{schedule.name}</CardTitle>
                      </div>
                    </div>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" disabled={!showPoeControls}>
                          <MoreVertical className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem
                          disabled={!showPoeControls}
                          onClick={() => handleScheduleOpenEdit(schedule)}
                        >
                          <Edit className="mr-2 h-4 w-4" />
                          {t('PoEPage.schedules.menu.edit')}
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          className="text-destructive"
                          disabled={!showPoeControls}
                          onClick={() => handleScheduleDelete(schedule)}
                        >
                          <Trash2 className="mr-2 h-4 w-4" />
                          {t('PoEPage.schedules.menu.delete')}
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    <div>
                      <span className="text-muted-foreground">{t('PoEPage.schedules.card.action')}</span>
                      <div className="font-medium">
                        {t('PoEPage.schedules.card.actionValue', {
                          action: t('PoEPage.schedules.actions.disable'),
                        })}
                      </div>
                    </div>
                    <div>
                      <span className="text-muted-foreground">{t('PoEPage.schedules.card.time')}</span>
                      <div className="font-medium">{schedule.power_off_time} - {schedule.power_on_time}</div>
                    </div>
                    <div>
                      <span className="text-muted-foreground">{t('PoEPage.schedules.card.days')}</span>
                      <div className="font-medium">
                        {(schedule.days_of_week ?? []).map(d => [
                          t('PoEPage.schedules.dayNames.mon'),
                          t('PoEPage.schedules.dayNames.tue'),
                          t('PoEPage.schedules.dayNames.wed'),
                          t('PoEPage.schedules.dayNames.thu'),
                          t('PoEPage.schedules.dayNames.fri'),
                          t('PoEPage.schedules.dayNames.sat'),
                          t('PoEPage.schedules.dayNames.sun'),
                        ][d]).join(', ')}
                      </div>
                    </div>
                    <div>
                      <span className="text-muted-foreground">{t('PoEPage.schedules.card.affects')}</span>
                      <div className="font-medium">{t('PoEPage.schedules.card.affectsValue', { count: (schedule.port_numbers ?? []).length })}</div>
                    </div>
                  </div>
                  {schedule.last_action_at && (
                    <div className="mt-3 flex items-center gap-2 text-sm text-muted-foreground">
                      <Clock className="h-4 w-4" />
                      {t('PoEPage.schedules.card.nextRun', {
                        time: new Date(schedule.last_action_at).toLocaleString(),
                      })}
                    </div>
                  )}
                </CardContent>
              </Card>
            ))}

            {poeSchedulesList.length === 0 && (
              <Card>
                <EmptyState
                  icon={Calendar}
                  title={t('PoEPage.schedules.empty.title')}
                  description={
                    showPoeControls
                      ? t('PoEPage.schedules.empty.description')
                      : poeDisabledReason || t('PoEPage.schedules.empty.notSupported')
                  }
                  action={
                    showPoeControls
                      ? {
                          label: t('PoEPage.schedules.create'),
                          icon: Plus,
                          onClick: handleScheduleOpenCreate,
                        }
                      : undefined
                  }
                />
              </Card>
            )}
          </div>
          )}
              </div>
            ),
          },
        ] satisfies PageTab[]}
      />

      {/* Port Configuration Dialog */}
      <Dialog open={portDialogOpen} onOpenChange={setPortDialogOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>{t('PoEPage.portDialog.title', { name: selectedPort?.port_name })}</DialogTitle>
            <DialogDescription>
              {t('PoEPage.portDialog.description')}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <Label>{t('PoEPage.portDialog.poeEnabled')}</Label>
              <Switch
                checked={portForm.poe_enabled}
                onCheckedChange={(checked) => setPortForm({ ...portForm, poe_enabled: checked })}
              />
            </div>

            <div className="space-y-2">
              <Label>{t('PoEPage.portDialog.poeMode')}</Label>
              <Select
                value={portForm.poe_mode}
                onValueChange={(v) => setPortForm({ ...portForm, poe_mode: v })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="auto">{t('PoEPage.portDialog.modeOptions.auto')}</SelectItem>
                  <SelectItem value="poe">802.3af (15.4W)</SelectItem>
                  <SelectItem value="poe+">802.3at (30W)</SelectItem>
                  <SelectItem value="poe++">802.3bt (60W)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label>{t('PoEPage.portDialog.powerLimit')}</Label>
                <span className="text-sm font-medium">{portForm.power_limit}W</span>
              </div>
              <Slider
                value={[portForm.power_limit]}
                onValueChange={([v]) => setPortForm({ ...portForm, power_limit: v })}
                max={60}
                min={1}
                step={0.5}
              />
            </div>

            <div className="space-y-2">
              <Label>{t('PoEPage.portDialog.priority')}</Label>
              <Select
                value={String(portForm.priority)}
                onValueChange={(v) => setPortForm({ ...portForm, priority: Number(v) })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">{t('PoEPage.portDialog.priorityOptions.critical')}</SelectItem>
                  <SelectItem value="2">{t('PoEPage.portDialog.priorityOptions.high')}</SelectItem>
                  <SelectItem value="3">{t('PoEPage.portDialog.priorityOptions.low')}</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {t('PoEPage.portDialog.priorityHelp')}
              </p>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setPortDialogOpen(false)}>
              {t('PoEPage.common.cancel')}
            </Button>
            <Button onClick={handlePortSave}>{t('PoEPage.portDialog.save')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Schedule Dialog */}
      <Dialog
        open={scheduleDialogOpen}
        onOpenChange={(open) => {
          setScheduleDialogOpen(open);
          if (!open) resetScheduleForm();
        }}
      >
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>{t('PoEPage.scheduleDialog.title')}</DialogTitle>
            <DialogDescription>
              {t('PoEPage.scheduleDialog.description')}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label>{t('PoEPage.scheduleDialog.name')}</Label>
              <Input
                value={scheduleForm.name}
                onChange={(e) => setScheduleForm({ ...scheduleForm, name: e.target.value })}
                placeholder={t('PoEPage.scheduleDialog.namePlaceholder')}
              />
            </div>

            <div className="space-y-2">
              <Label>{t('PoEPage.scheduleDialog.device')}</Label>
              <Select
                value={scheduleForm.device_id || undefined}
                onValueChange={(v) =>
                  setScheduleForm({ ...scheduleForm, device_id: v, port_numbers: [] })
                }
              >
                <SelectTrigger>
                  <SelectValue placeholder={t('PoEPage.scheduleDialog.devicePlaceholder')} />
                </SelectTrigger>
                <SelectContent>
                  {devices.map((device) => (
                    <SelectItem key={device.device_id} value={device.device_id}>
                      {device.device_name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>{t('PoEPage.scheduleDialog.ports')}</Label>
              {!scheduleForm.device_id ? (
                <p className="text-sm text-muted-foreground">
                  {t('PoEPage.scheduleDialog.portsSelectDeviceFirst')}
                </p>
              ) : scheduleDevicePortsLoading ? (
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <RefreshCw className="h-4 w-4 animate-spin" />
                  {t('PoEPage.scheduleDialog.portsLoading')}
                </div>
              ) : (scheduleDevicePorts ?? []).length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  {t('PoEPage.scheduleDialog.portsEmpty')}
                </p>
              ) : (
                <div className="flex flex-wrap gap-1 rounded-md border p-2 max-h-40 overflow-y-auto">
                  {(scheduleDevicePorts ?? []).map((port) => {
                    const selected = scheduleForm.port_numbers.includes(port.port_index);
                    return (
                      <Button
                        key={port.port_id}
                        type="button"
                        variant={selected ? 'default' : 'outline'}
                        size="sm"
                        className="h-8"
                        onClick={() => {
                          const next = selected
                            ? scheduleForm.port_numbers.filter((n) => n !== port.port_index)
                            : [...scheduleForm.port_numbers, port.port_index];
                          setScheduleForm({ ...scheduleForm, port_numbers: next });
                        }}
                      >
                        {port.port_name}
                      </Button>
                    );
                  })}
                </div>
              )}
              {scheduleForm.device_id && scheduleForm.port_numbers.length === 0 && (
                <p className="text-xs text-muted-foreground">
                  {t('PoEPage.scheduleDialog.portsRequired')}
                </p>
              )}
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>{t('PoEPage.scheduleDialog.startTime')}</Label>
                <Input
                  type="time"
                  value={scheduleForm.start_time}
                  onChange={(e) => setScheduleForm({ ...scheduleForm, start_time: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label>{t('PoEPage.scheduleDialog.endTime')}</Label>
                <Input
                  type="time"
                  value={scheduleForm.end_time}
                  onChange={(e) => setScheduleForm({ ...scheduleForm, end_time: e.target.value })}
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label>{t('PoEPage.scheduleDialog.days')}</Label>
              <div className="flex gap-1">
                {[
                  t('PoEPage.scheduleDialog.dayInitials.mon'),
                  t('PoEPage.scheduleDialog.dayInitials.tue'),
                  t('PoEPage.scheduleDialog.dayInitials.wed'),
                  t('PoEPage.scheduleDialog.dayInitials.thu'),
                  t('PoEPage.scheduleDialog.dayInitials.fri'),
                  t('PoEPage.scheduleDialog.dayInitials.sat'),
                  t('PoEPage.scheduleDialog.dayInitials.sun'),
                ].map((day, i) => (
                  <Button
                    key={i}
                    variant={scheduleForm.days_of_week.includes(i) ? 'default' : 'outline'}
                    size="sm"
                    className="w-9"
                    onClick={() => {
                      const days = scheduleForm.days_of_week.includes(i)
                        ? scheduleForm.days_of_week.filter(d => d !== i)
                        : [...scheduleForm.days_of_week, i];
                      setScheduleForm({ ...scheduleForm, days_of_week: days });
                    }}
                  >
                    {day}
                  </Button>
                ))}
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setScheduleDialogOpen(false)}>
              {t('PoEPage.common.cancel')}
            </Button>
            <Button
              onClick={handleScheduleSave}
              disabled={
                scheduleSaving ||
                !scheduleForm.name.trim() ||
                !scheduleForm.device_id ||
                scheduleForm.port_numbers.length === 0
              }
            >
              {editingScheduleId ? t('PoEPage.schedules.menu.edit') : t('PoEPage.schedules.create')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      </div>
  );
}
