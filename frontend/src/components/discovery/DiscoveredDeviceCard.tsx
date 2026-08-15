// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * DiscoveredDeviceCard - Card showing a discovered device with status & actions.
 */

import {
  Router,
  Camera,
  Wifi,
  Monitor,
  Server,
  Printer,
  HardDrive,
  Shield,
  MoreVertical,
  CheckCircle2,
  AlertCircle,
  Circle,
  Copy,
  ExternalLink,
  Eye,
  Trash2,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from '@/components/ui/dropdown-menu';
import { cn } from '@/lib/utils';

const PORT_SERVICES: Record<number, string> = {
  22: 'SSH', 23: 'Telnet', 53: 'DNS', 80: 'HTTP', 161: 'SNMP',
  443: 'HTTPS', 554: 'RTSP', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
  8291: 'WinBox', 8728: 'MikroTik API', 5060: 'SIP', 3389: 'RDP',
  8006: 'Proxmox', 9090: 'Cockpit', 8834: 'Nessus',
  162: 'SNMP-Trap', 1883: 'MQTT', 5000: 'UPnP', 7547: 'TR-069',
};

const DEVICE_ICONS: Record<string, React.ElementType> = {
  router: Router,
  switch: HardDrive,
  access_point: Wifi,
  camera: Camera,
  server: Server,
  workstation: Monitor,
  printer: Printer,
  firewall: Shield,
};

export interface DiscoveredDevice {
  ip: string;
  mac?: string;
  hostname?: string;
  vendor?: string;
  device_type?: string;
  open_ports?: number[];
  fingerprint?: Record<string, unknown>;
  confidence?: number;
  driver_match?: {
    driver_id: string;
    driver_name: string;
    confidence: number;
    reasons?: string[];
    is_manageable?: boolean;
  };
  is_adopted?: boolean;
  adopted_device_id?: string;
  status?: 'new' | 'matched' | 'adopted' | 'ignored';
}

interface DiscoveredDeviceCardProps {
  device: DiscoveredDevice;
  onAdopt?: (device: DiscoveredDevice) => void;
  onViewDetails?: (device: DiscoveredDevice) => void;
  onIgnore?: (device: DiscoveredDevice) => void;
  selectionMode?: boolean;
  selected?: boolean;
  onSelectionChange?: (device: DiscoveredDevice, checked: boolean) => void;
}

function getConfidenceLabel(conf: number) {
  if (conf >= 80) return { labelKey: 'confidence.high', color: 'bg-green-500/10 text-green-700 dark:text-green-400 border-green-500/20' };
  if (conf >= 50) return { labelKey: 'confidence.good', color: 'bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 border-yellow-500/20' };
  return { labelKey: 'confidence.low', color: 'bg-orange-500/10 text-orange-700 dark:text-orange-400 border-orange-500/20' };
}

function getStatusInfo(device: DiscoveredDevice) {
  if (device.is_adopted || device.status === 'adopted') {
    return { icon: CheckCircle2, color: 'text-green-500', labelKey: 'status.adopted' };
  }
  if (device.driver_match || device.status === 'matched') {
    return { icon: AlertCircle, color: 'text-blue-500', labelKey: 'status.matched' };
  }
  if (device.status === 'ignored') {
    return { icon: Circle, color: 'text-muted-foreground', labelKey: 'status.ignored' };
  }
  return { icon: Circle, color: 'text-yellow-500', labelKey: 'status.discovered' };
}

export default function DiscoveredDeviceCard({
  device,
  onAdopt,
  onViewDetails,
  onIgnore,
  selectionMode,
  selected,
  onSelectionChange,
}: DiscoveredDeviceCardProps) {
  const { t } = useTranslation('common');
  const DeviceIcon = DEVICE_ICONS[device.device_type || ''] || Monitor;
  const statusInfo = getStatusInfo(device);
  const StatusIcon = statusInfo.icon;
  const isAdopted = device.is_adopted || device.status === 'adopted';
  const hasDriver = !!device.driver_match;
  const conf = device.driver_match?.confidence ?? device.confidence;
  const confInfo = conf != null ? getConfidenceLabel(conf) : null;

  return (
    <Card className={cn(
      'transition-all hover:shadow-md group',
      selected && 'ring-2 ring-primary',
      isAdopted && 'opacity-70',
    )}>
      <CardContent noOffset className="p-4">
        {/* Top row: selection + icon + identity */}
        <div className="flex items-start gap-3 mb-3">
          {selectionMode && (
            <Checkbox
              checked={selected}
              onCheckedChange={(v) => onSelectionChange?.(device, !!v)}
              className="mt-1"
            />
          )}
          <div className={cn(
            'w-10 h-10 rounded-lg flex items-center justify-center shrink-0',
            isAdopted ? 'bg-green-500/10' : 'bg-primary/10',
          )}>
            <DeviceIcon className={cn('h-5 w-5', isAdopted ? 'text-green-500' : 'text-primary')} />
          </div>

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-0.5">
              <span className="font-mono text-sm font-semibold truncate">{device.ip}</span>
              <StatusIcon className={cn('h-3.5 w-3.5 shrink-0', statusInfo.color)} />
            </div>
            {device.hostname && (
              <p className="text-xs text-muted-foreground truncate">{device.hostname}</p>
            )}
            {device.mac && (
              <p className="text-[10px] text-muted-foreground/70 font-mono">{device.mac}</p>
            )}
          </div>

          {/* Dropdown menu */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="h-7 w-7 opacity-0 group-hover:opacity-100 transition-opacity">
                <MoreVertical className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => onViewDetails?.(device)}>
                <Eye className="h-4 w-4 mr-2" /> {t('DiscoveredDeviceCard.actions.viewDetails')}
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => navigator.clipboard.writeText(device.ip)}>
                <Copy className="h-4 w-4 mr-2" /> {t('DiscoveredDeviceCard.actions.copyIp')}
              </DropdownMenuItem>
              {device.open_ports?.includes(80) || device.open_ports?.includes(443) ? (
                <DropdownMenuItem onClick={() => {
                  const proto = device.open_ports?.includes(443) ? 'https' : 'http';
                  window.open(`${proto}://${device.ip}`, '_blank', 'noopener,noreferrer');
                }}>
                  <ExternalLink className="h-4 w-4 mr-2" /> {t('DiscoveredDeviceCard.actions.openInBrowser')}
                </DropdownMenuItem>
              ) : null}
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={() => onIgnore?.(device)}
                className="text-muted-foreground"
              >
                <Trash2 className="h-4 w-4 mr-2" /> {t('DiscoveredDeviceCard.actions.ignoreDevice')}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>

        {/* Badges row: vendor + device type + confidence */}
        <div className="flex flex-wrap gap-1.5 mb-3">
          {device.vendor && (
            <Badge variant="secondary" className="text-[10px]">{device.vendor}</Badge>
          )}
          {device.device_type && (
            <Badge variant="outline" className="text-[10px] capitalize">{device.device_type.replace('_', ' ')}</Badge>
          )}
          {confInfo && (
            <Badge variant="outline" className={cn('text-[10px]', confInfo.color)}>{t(`DiscoveredDeviceCard.${confInfo.labelKey}`)}</Badge>
          )}
        </div>

        {/* Open ports */}
        {device.open_ports && device.open_ports.length > 0 && (
          <div className="flex flex-wrap gap-1 mb-3">
            {device.open_ports.slice(0, 5).map(port => (
              <Badge key={port} variant="outline" className="text-[10px] font-mono bg-muted/50">
                {PORT_SERVICES[port] || port}
              </Badge>
            ))}
            {device.open_ports.length > 5 && (
              <Badge variant="outline" className="text-[10px] text-muted-foreground">
                {t('DiscoveredDeviceCard.morePorts', { count: device.open_ports.length - 5 })}
              </Badge>
            )}
          </div>
        )}

        {/* Driver match info */}
        {device.driver_match && (
          <div className="p-2 rounded bg-muted/50 text-xs mb-3">
            <span className="text-muted-foreground">{t('DiscoveredDeviceCard.driverLabel')} </span>
            <span className="font-medium">{device.driver_match.driver_name}</span>
            {device.driver_match.is_manageable && (
              <Badge variant="secondary" className="ml-2 text-[9px]">{t('DiscoveredDeviceCard.manageable')}</Badge>
            )}
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center gap-2">
          {!isAdopted ? (
            <>
              <Button
                size="sm"
                className="flex-1 text-xs"
                disabled={!hasDriver}
                onClick={() => onAdopt?.(device)}
              >
                {t('DiscoveredDeviceCard.actions.adoptDevice')}
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="text-xs"
                onClick={() => onViewDetails?.(device)}
              >
                {t('DiscoveredDeviceCard.actions.details')}
              </Button>
            </>
          ) : (
            <div className="flex items-center gap-2 text-xs text-green-600 dark:text-green-400 w-full">
              <CheckCircle2 className="h-3.5 w-3.5" />
              <span>{t('DiscoveredDeviceCard.deviceAdopted')}</span>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
