// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2026 FreeSDN
/**
 * Shared controller + site picker for the gateway-* pages. Renders two
 * dropdowns side-by-side; both must be selected before the page loads
 * live data. Falls back gracefully when the org has no Omada
 * controllers configured.
 */

import { useTranslation } from 'react-i18next';

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useSiteStore } from '@/stores/siteStore';

interface ControllerLite {
  id: string;
  name: string;
  site_id?: string;
}

interface Props {
  controllers: ControllerLite[];
  controllerId: string | null;
  onControllerChange: (id: string | null) => void;
  siteId: string | null;
  onSiteChange: (id: string | null) => void;
}

export function GatewayControllerSitePicker({
  controllers,
  controllerId,
  onControllerChange,
  siteId,
  onSiteChange,
}: Props) {
  const { t } = useTranslation('gateway');
  const sites = useSiteStore((s) => s.sites);

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      <div>
        <label className="mb-1 block text-xs font-medium text-muted-foreground">
          {t('GatewayControllerSitePicker.controller.label')}
        </label>
        <Select
          value={controllerId ?? ''}
          onValueChange={(v) => onControllerChange(v || null)}
        >
          <SelectTrigger>
            <SelectValue
              placeholder={t('GatewayControllerSitePicker.controller.placeholder')}
            />
          </SelectTrigger>
          <SelectContent>
            {controllers.length === 0 ? (
              <div className="p-3 text-xs text-muted-foreground">
                {t('GatewayControllerSitePicker.controller.empty')}
              </div>
            ) : (
              controllers.map((c) => (
                <SelectItem key={c.id} value={c.id}>
                  {c.name}
                </SelectItem>
              ))
            )}
          </SelectContent>
        </Select>
      </div>

      <div>
        <label className="mb-1 block text-xs font-medium text-muted-foreground">
          {t('GatewayControllerSitePicker.site.label')}
        </label>
        <Select
          value={siteId ?? ''}
          onValueChange={(v) => onSiteChange(v || null)}
        >
          <SelectTrigger>
            <SelectValue
              placeholder={t('GatewayControllerSitePicker.site.placeholder')}
            />
          </SelectTrigger>
          <SelectContent>
            {sites.length === 0 ? (
              <div className="p-3 text-xs text-muted-foreground">
                {t('GatewayControllerSitePicker.site.empty')}
              </div>
            ) : (
              sites.map((s) => (
                <SelectItem key={s.id} value={s.id}>
                  {s.name}
                </SelectItem>
              ))
            )}
          </SelectContent>
        </Select>
      </div>
    </div>
  );
}
