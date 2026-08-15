// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * DeviceDetailsDialog - Full device info dialog with 6 info cards.
 *
 * Cards: Network Info, Classification, Open Ports, Driver Match, All Matches, Suggestions
 */

import {
  Network,
  Fingerprint,
  Globe,
  Copy,
  CheckCircle2,
  XCircle,
  Server,
  Star,
  Info,
  Terminal,
} from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useTranslation } from 'react-i18next';
import { cn } from '@/lib/utils';
import type { DiscoveredDevice } from './DiscoveredDeviceCard';

interface DeviceDetailsDialogProps {
  device: DiscoveredDevice | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onAdopt?: (device: DiscoveredDevice) => void;
  allDriverMatches?: Array<{
    driver_id: string;
    driver_name: string;
    confidence: number;
    reasons?: string[];
    is_manageable?: boolean;
  }>;
  suggestions?: string[];
}

const PORT_SERVICES: Record<number, string> = {
  22: 'SSH', 23: 'Telnet', 53: 'DNS', 80: 'HTTP', 161: 'SNMP',
  443: 'HTTPS', 554: 'RTSP', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
  8291: 'WinBox', 8728: 'MikroTik API', 5060: 'SIP', 3389: 'RDP',
  8006: 'Proxmox', 9090: 'Cockpit', 1883: 'MQTT', 5000: 'UPnP',
  7547: 'TR-069', 21: 'FTP', 25: 'SMTP', 110: 'POP3', 143: 'IMAP',
  3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB',
};

function CopyableField({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between text-sm py-1">
      <span className="text-muted-foreground">{label}</span>
      <div className="flex items-center gap-1.5">
        <span className="font-mono text-xs">{value}</span>
        <Button
          variant="ghost"
          size="icon"
          className="h-5 w-5"
          onClick={() => navigator.clipboard.writeText(value)}
        >
          <Copy className="h-3 w-3" />
        </Button>
      </div>
    </div>
  );
}

function confidenceColor(c: number) {
  if (c >= 80) return 'text-green-600 dark:text-green-400';
  if (c >= 50) return 'text-yellow-600 dark:text-yellow-400';
  return 'text-orange-600 dark:text-orange-400';
}

export default function DeviceDetailsDialog({
  device,
  open,
  onOpenChange,
  onAdopt,
  allDriverMatches = [],
  suggestions = [],
}: DeviceDetailsDialogProps) {
  const { t } = useTranslation('common');
  if (!device) return null;

  const isAdopted = device.is_adopted || device.status === 'adopted';
  const hasHttp = device.open_ports?.includes(80) || device.open_ports?.includes(8080);
  const hasHttps = device.open_ports?.includes(443) || device.open_ports?.includes(8443);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Server className="h-5 w-5" />
            {t('DeviceDetailsDialog.title', { ip: device.ip })}
            {isAdopted && (
              <Badge className="bg-green-500/10 text-green-700 dark:text-green-400 border-green-500/20">
                {t('DeviceDetailsDialog.status.adopted')}
              </Badge>
            )}
          </DialogTitle>
        </DialogHeader>

        {/* Quick actions */}
        <div className="flex gap-2 flex-wrap">
          {hasHttp && (
            <Button size="sm" variant="outline" className="text-xs gap-1.5" onClick={() => window.open(`http://${device.ip}`, '_blank', 'noopener,noreferrer')}>
              <Globe className="h-3.5 w-3.5" /> {t('DeviceDetailsDialog.actions.openHttp')}
            </Button>
          )}
          {hasHttps && (
            <Button size="sm" variant="outline" className="text-xs gap-1.5" onClick={() => window.open(`https://${device.ip}`, '_blank', 'noopener,noreferrer')}>
              <Globe className="h-3.5 w-3.5" /> {t('DeviceDetailsDialog.actions.openHttps')}
            </Button>
          )}
          {!isAdopted && onAdopt && (
            <Button size="sm" className="text-xs gap-1.5 ml-auto" onClick={() => onAdopt(device)}>
              {t('DeviceDetailsDialog.actions.adoptDevice')}
            </Button>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-2">
          {/* Card 1: Network Info */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Network className="h-4 w-4 text-primary" /> {t('DeviceDetailsDialog.cards.networkInfo')}
              </CardTitle>
            </CardHeader>
            <CardContent className="text-sm space-y-1">
              <CopyableField label={t('DeviceDetailsDialog.fields.ipAddress')} value={device.ip} />
              {device.mac && <CopyableField label={t('DeviceDetailsDialog.fields.macAddress')} value={device.mac} />}
              {device.hostname && <CopyableField label={t('DeviceDetailsDialog.fields.hostname')} value={device.hostname} />}
              {device.vendor && (
                <div className="flex items-center justify-between text-sm py-1">
                  <span className="text-muted-foreground">{t('DeviceDetailsDialog.fields.manufacturer')}</span>
                  <Badge variant="secondary">{device.vendor}</Badge>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Card 2: Classification */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Fingerprint className="h-4 w-4 text-primary" /> {t('DeviceDetailsDialog.cards.classification')}
              </CardTitle>
            </CardHeader>
            <CardContent className="text-sm space-y-2">
              <div className="flex items-center justify-between py-1">
                <span className="text-muted-foreground">{t('DeviceDetailsDialog.fields.deviceType')}</span>
                <Badge variant="outline" className="capitalize">{device.device_type?.replace('_', ' ') || t('DeviceDetailsDialog.fields.unknown')}</Badge>
              </div>
              {device.confidence != null && (
                <div className="flex items-center justify-between py-1">
                  <span className="text-muted-foreground">{t('DeviceDetailsDialog.fields.confidence')}</span>
                  <span className={cn('font-medium', confidenceColor(device.confidence))}>
                    {device.confidence}%
                  </span>
                </div>
              )}
              {device.driver_match && (
                <>
                  <div className="flex items-center justify-between py-1">
                    <span className="text-muted-foreground">{t('DeviceDetailsDialog.fields.manageable')}</span>
                    {device.driver_match.is_manageable ? (
                      <CheckCircle2 className="h-4 w-4 text-green-500" />
                    ) : (
                      <XCircle className="h-4 w-4 text-muted-foreground" />
                    )}
                  </div>
                </>
              )}
              {device.fingerprint && Object.keys(device.fingerprint).length > 0 && (
                <div className="pt-1">
                  <span className="text-xs text-muted-foreground">{t('DeviceDetailsDialog.fields.fingerprintAvailable')}</span>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Card 3: Open Ports */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Terminal className="h-4 w-4 text-primary" /> {t('DeviceDetailsDialog.cards.openPorts')}
                {device.open_ports && (
                  <Badge variant="secondary" className="text-[10px] ml-auto">{device.open_ports.length}</Badge>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {device.open_ports && device.open_ports.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {device.open_ports.map(port => (
                    <Badge
                      key={port}
                      variant="outline"
                      className="text-xs font-mono cursor-default"
                      title={t('DeviceDetailsDialog.fields.portTooltip', { port })}
                    >
                      {port}
                      {PORT_SERVICES[port] && (
                        <span className="ml-1 text-muted-foreground font-sans">{PORT_SERVICES[port]}</span>
                      )}
                    </Badge>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">{t('DeviceDetailsDialog.empty.noOpenPorts')}</p>
              )}
            </CardContent>
          </Card>

          {/* Card 4: Primary Driver Match */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Star className="h-4 w-4 text-amber-500" /> {t('DeviceDetailsDialog.cards.driverMatch')}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {device.driver_match ? (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-sm">{device.driver_match.driver_name}</span>
                    <span className={cn('text-sm font-bold', confidenceColor(device.driver_match.confidence))}>
                      {device.driver_match.confidence}%
                    </span>
                  </div>
                  {device.driver_match.reasons && device.driver_match.reasons.length > 0 && (
                    <div className="space-y-1">
                      {device.driver_match.reasons.map((r, i) => (
                        <div key={i} className="flex items-start gap-1.5 text-xs text-muted-foreground">
                          <CheckCircle2 className="h-3 w-3 mt-0.5 text-green-500 shrink-0" />
                          {r}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">{t('DeviceDetailsDialog.empty.noDriverMatch')}</p>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Card 5: All Driver Matches (full-width) */}
        {allDriverMatches.length > 1 && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                {t('DeviceDetailsDialog.cards.allDriverMatches')}
                <Badge variant="secondary" className="text-[10px]">{allDriverMatches.length}</Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {allDriverMatches.map((match, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between p-2 rounded-lg bg-muted/30 text-sm"
                  >
                    <div className="flex items-center gap-2">
                      {i === 0 && <Star className="h-3.5 w-3.5 text-amber-500" />}
                      <span className="font-medium">{match.driver_name}</span>
                      {match.is_manageable && (
                        <Badge variant="outline" className="text-[9px]">{t('DeviceDetailsDialog.fields.manageable')}</Badge>
                      )}
                    </div>
                    <span className={cn('font-bold text-xs', confidenceColor(match.confidence))}>
                      {match.confidence}%
                    </span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Card 6: Suggestions */}
        {suggestions.length > 0 && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Info className="h-4 w-4 text-blue-500" /> {t('DeviceDetailsDialog.cards.suggestions')}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-1.5">
                {suggestions.map((s, i) => (
                  <li key={i} className="text-xs text-muted-foreground flex items-start gap-2">
                    <span className="text-blue-500 mt-0.5">•</span>
                    {s}
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        )}
      </DialogContent>
    </Dialog>
  );
}
