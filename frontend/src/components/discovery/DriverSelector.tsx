// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * DriverSelector - Searchable driver selection list with recommendations.
 */

import { useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { Search, Star, Cpu, WifiIcon, Shield, Camera, Server, Check } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

export interface DriverInfo {
  id: string;
  name: string;
  vendor: string;
  device_types: string[];
  capabilities?: string[];
  version?: string;
  description?: string;
}

interface DriverSelectorProps {
  drivers: DriverInfo[];
  selectedDriverId?: string;
  recommendedDriverId?: string;
  onSelect: (driver: DriverInfo) => void;
}

const VENDOR_ICONS: Record<string, React.ElementType> = {
  'tp-link': WifiIcon,
  omada: WifiIcon,
  hikvision: Camera,
  mikrotik: Cpu,
  opnsense: Shield,
  pfsense: Shield,
  grandstream: Server,
};

export default function DriverSelector({
  drivers,
  selectedDriverId,
  recommendedDriverId,
  onSelect,
}: DriverSelectorProps) {
  const { t } = useTranslation('common');
  const [search, setSearch] = useState('');

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    const result = drivers.filter(d =>
      !q ||
      d.name.toLowerCase().includes(q) ||
      d.vendor.toLowerCase().includes(q) ||
      d.device_types.some(t => t.toLowerCase().includes(q))
    );
    // Sort: recommended first, then alphabetical
    return result.sort((a, b) => {
      if (a.id === recommendedDriverId) return -1;
      if (b.id === recommendedDriverId) return 1;
      return a.name.localeCompare(b.name);
    });
  }, [drivers, search, recommendedDriverId]);

  return (
    <div className="space-y-3">
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder={t('DriverSelector.searchPlaceholder')}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-9"
        />
      </div>
      <div className="max-h-[300px] overflow-y-auto space-y-1">
        {filtered.length === 0 && (
          <p className="text-sm text-muted-foreground text-center py-8">{t('DriverSelector.empty')}</p>
        )}
        {filtered.map(driver => {
          const isRecommended = driver.id === recommendedDriverId;
          const isSelected = driver.id === selectedDriverId;
          const VendorIcon = VENDOR_ICONS[driver.vendor?.toLowerCase()] || Server;

          return (
            <div
              key={driver.id}
              onClick={() => onSelect(driver)}
              className={cn(
                'p-3 rounded-lg border cursor-pointer transition-all flex items-start gap-3',
                isSelected
                  ? 'border-primary bg-primary/5 ring-1 ring-primary'
                  : 'border-border hover:border-primary/30 hover:bg-muted/30',
              )}
            >
              <div className="w-8 h-8 rounded flex items-center justify-center bg-muted shrink-0">
                <VendorIcon className="h-4 w-4" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-0.5">
                  <span className="text-sm font-medium truncate">{driver.name}</span>
                  {isRecommended && (
                    <Badge className="text-[9px] bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/20">
                      <Star className="h-2.5 w-2.5 mr-0.5" /> {t('DriverSelector.recommended')}
                    </Badge>
                  )}
                  {isSelected && <Check className="h-4 w-4 text-primary shrink-0" />}
                </div>
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <span>{driver.vendor}</span>
                  {driver.version && <span>v{driver.version}</span>}
                </div>
                <div className="flex flex-wrap gap-1 mt-1.5">
                  {driver.device_types.slice(0, 3).map(t => (
                    <Badge key={t} variant="secondary" className="text-[9px] capitalize">
                      {t.replace('_', ' ')}
                    </Badge>
                  ))}
                  {driver.capabilities?.slice(0, 2).map(c => (
                    <Badge key={c} variant="outline" className="text-[9px]">{c}</Badge>
                  ))}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
